package auth

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/stringutils"
)

var (
	// ErrSessionUserNotFound indicates that no authenticated user is associated with the session.
	ErrSessionUserNotFound = errors.New("session user not found")
)

type tokenResult struct {
	AccessToken  *AccessToken
	RefreshToken *RefreshToken
	Scope        []string
}

type tokenError struct {
	code            string
	description     string
	status          int
	wwwAuthenticate bool
}

func (e *tokenError) Error() string {
	if e.description != "" {
		return fmt.Sprintf("%s: %s", e.code, e.description)
	}
	return e.code
}

func newTokenError(code, description string, status int, wwwAuthenticate bool) error {
	return &tokenError{
		code:            code,
		description:     description,
		status:          status,
		wwwAuthenticate: wwwAuthenticate,
	}
}

func processTokenRequest(r *http.Request, store *Store, accessTTL, refreshTTL time.Duration) (*tokenResult, error) {
	if store == nil {
		return nil, newTokenError("server_error", "token service misconfigured", http.StatusInternalServerError, false)
	}
	if accessTTL <= 0 || refreshTTL <= 0 {
		return nil, newTokenError("server_error", "token expiration not configured", http.StatusInternalServerError, false)
	}

	if r.Method != http.MethodPost {
		return nil, newTokenError("invalid_request", "token endpoint requires POST", http.StatusBadRequest, false)
	}

	if err := r.ParseForm(); err != nil {
		return nil, newTokenError("invalid_request", "unable to parse request body", http.StatusBadRequest, false)
	}

	grantType := strings.TrimSpace(r.Form.Get("grant_type"))
	if grantType == "" {
		return nil, newTokenError("invalid_request", "grant_type is required", http.StatusBadRequest, false)
	}
	if grantType != "authorization_code" {
		return nil, newTokenError("unsupported_grant_type", "only authorization_code is supported", http.StatusBadRequest, false)
	}

	clientID, clientSecret, hasBasic := r.BasicAuth()
	if !hasBasic {
		clientID = strings.TrimSpace(r.Form.Get("client_id"))
		clientSecret = r.Form.Get("client_secret")
	}
	clientID = strings.TrimSpace(clientID)
	clientSecret = strings.TrimSpace(clientSecret)

	if clientID == "" {
		return nil, newTokenError("invalid_client", "client authentication failed", http.StatusUnauthorized, true)
	}

	client, err := store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, newTokenError("invalid_client", "client authentication failed", http.StatusUnauthorized, true)
		}
		return nil, newTokenError("server_error", "unable to load client", http.StatusInternalServerError, false)
	}

	if clientSecret == "" || subtle.ConstantTimeCompare([]byte(client.ClientSecret), []byte(clientSecret)) != 1 {
		return nil, newTokenError("invalid_client", "client authentication failed", http.StatusUnauthorized, true)
	}

	codeParam := strings.TrimSpace(r.Form.Get("code"))
	if codeParam == "" {
		return nil, newTokenError("invalid_request", "code is required", http.StatusBadRequest, false)
	}

	redirectParam := strings.TrimSpace(r.Form.Get("redirect_uri"))

	authCode, err := store.GetAuthorizationCodeByCode(r.Context(), codeParam)
	if err != nil {
		if errors.Is(err, ErrAuthorizationCodeNotFound) {
			return nil, newTokenError("invalid_grant", "authorization code is invalid or expired", http.StatusBadRequest, false)
		}
		return nil, newTokenError("server_error", "unable to load authorization code", http.StatusInternalServerError, false)
	}

	if authCode.Code == nil || *authCode.Code != codeParam {
		return nil, newTokenError("invalid_grant", "authorization code is invalid or expired", http.StatusBadRequest, false)
	}

	if authCode.ClientID != client.ID {
		return nil, newTokenError("invalid_grant", "authorization code was not issued to this client", http.StatusBadRequest, false)
	}

	if time.Now().UTC().After(authCode.ExpiresAt) {
		return nil, newTokenError("invalid_grant", "authorization code has expired", http.StatusBadRequest, false)
	}

	if authCode.RedirectURI != "" {
		if redirectParam == "" {
			return nil, newTokenError("invalid_request", "redirect_uri is required", http.StatusBadRequest, false)
		}
		if redirectParam != authCode.RedirectURI {
			return nil, newTokenError("invalid_grant", "redirect_uri mismatch", http.StatusBadRequest, false)
		}
	}

	accessToken, err := store.IssueAccessToken(r.Context(), IssueAccessTokenParams{
		SessionID: authCode.SessionID,
		ClientID:  client.ID,
		Scope:     authCode.Scope,
		TTL:       accessTTL,
	})
	if err != nil {
		if errors.Is(err, ErrSessionUserNotFound) {
			return nil, newTokenError("invalid_grant", "session is not authenticated", http.StatusBadRequest, false)
		}
		return nil, newTokenError("server_error", "unable to issue access token", http.StatusInternalServerError, false)
	}

	refreshToken, err := store.IssueRefreshToken(r.Context(), IssueRefreshTokenParams{
		SessionID: authCode.SessionID,
		ClientID:  client.ID,
		Scope:     authCode.Scope,
		TTL:       refreshTTL,
	})
	if err != nil {
		_ = store.deleteAccessTokenByID(r.Context(), accessToken.ID)
		if errors.Is(err, ErrSessionUserNotFound) {
			return nil, newTokenError("invalid_grant", "session is not authenticated", http.StatusBadRequest, false)
		}
		return nil, newTokenError("server_error", "unable to issue refresh token", http.StatusInternalServerError, false)
	}

	if err := store.DeleteAuthorizationCode(r.Context(), authCode.SessionID); err != nil {
		_ = store.deleteAccessTokenByID(r.Context(), accessToken.ID)
		_ = store.deleteRefreshTokenByID(r.Context(), refreshToken.ID)
		return nil, newTokenError("server_error", "unable to consume authorization code", http.StatusInternalServerError, false)
	}

	return &tokenResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		Scope:        authCode.Scope,
	}, nil
}

// IssueAccessTokenParams captures the inputs required to mint a bearer token.
type IssueAccessTokenParams struct {
	SessionID string
	ClientID  string
	UserID    string
	Scope     []string
	TTL       time.Duration
}

// IssueRefreshTokenParams captures the inputs required to mint a refresh token.
type IssueRefreshTokenParams struct {
	SessionID string
	ClientID  string
	UserID    string
	Scope     []string
	TTL       time.Duration
}

// IssueAccessToken creates and persists a short-lived bearer token per RFC 6750.
func (s *Store) IssueAccessToken(ctx context.Context, params IssueAccessTokenParams) (*AccessToken, error) {
	if strings.TrimSpace(params.SessionID) == "" {
		return nil, logger.LogErr(errors.New("session id is required"))
	}
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, logger.LogErr(errors.New("client id is required"))
	}
	if params.TTL <= 0 {
		return nil, logger.LogErr(errors.New("access token ttl must be greater than zero"))
	}

	userID := strings.TrimSpace(params.UserID)
	if userID == "" {
		var err error
		userID, err = s.lookupUserIDForSession(ctx, params.SessionID)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now().UTC()
	expiresAt := now.Add(params.TTL)
	tokenID := uuid.NewString()
	tokenValue := uuid.NewString()
	scope := strings.Join(params.Scope, " ")

	_, err := s.db.ExecContext(ctx, `
        INSERT INTO access_token (
            id,
            token,
            session_id,
            client_id,
            user_id,
            scope,
            expires_at,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
		tokenID,
		tokenValue,
		params.SessionID,
		params.ClientID,
		userID,
		stringutils.NullIfBlank(scope),
		expiresAt,
		now,
	)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("insert access token for session %s: %w", params.SessionID, err))
	}

	return &AccessToken{
		ID:        tokenID,
		Token:     tokenValue,
		SessionID: params.SessionID,
		ClientID:  params.ClientID,
		UserID:    userID,
		Scope:     append([]string(nil), params.Scope...),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

// IssueRefreshToken creates and persists a long-lived refresh token per RFC 6749 §6.
func (s *Store) IssueRefreshToken(ctx context.Context, params IssueRefreshTokenParams) (*RefreshToken, error) {
	if strings.TrimSpace(params.SessionID) == "" {
		return nil, logger.LogErr(errors.New("session id is required"))
	}
	if strings.TrimSpace(params.ClientID) == "" {
		return nil, logger.LogErr(errors.New("client id is required"))
	}
	if params.TTL <= 0 {
		return nil, logger.LogErr(errors.New("refresh token ttl must be greater than zero"))
	}

	userID := strings.TrimSpace(params.UserID)
	if userID == "" {
		var err error
		userID, err = s.lookupUserIDForSession(ctx, params.SessionID)
		if err != nil {
			return nil, err
		}
	}

	now := time.Now().UTC()
	expiresAt := now.Add(params.TTL)
	tokenID := uuid.NewString()
	tokenValue := uuid.NewString()
	scope := strings.Join(params.Scope, " ")

	if _, err := s.db.ExecContext(ctx, `
        DELETE FROM refresh_token
        WHERE session_id = ?
    `, params.SessionID); err != nil {
		return nil, logger.LogErr(fmt.Errorf("delete existing refresh token for session %s: %w", params.SessionID, err))
	}

	_, err := s.db.ExecContext(ctx, `
        INSERT INTO refresh_token (
            id,
            token,
            session_id,
            client_id,
            user_id,
            scope,
            expires_at,
            created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `,
		tokenID,
		tokenValue,
		params.SessionID,
		params.ClientID,
		userID,
		stringutils.NullIfBlank(scope),
		expiresAt,
		now,
	)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("insert refresh token for session %s: %w", params.SessionID, err))
	}

	return &RefreshToken{
		ID:        tokenID,
		Token:     tokenValue,
		SessionID: params.SessionID,
		ClientID:  params.ClientID,
		UserID:    userID,
		Scope:     append([]string(nil), params.Scope...),
		ExpiresAt: expiresAt,
		CreatedAt: now,
	}, nil
}

func (s *Store) lookupUserIDForSession(ctx context.Context, sessionID string) (string, error) {
	var userID string
	if err := s.db.QueryRowContext(ctx, `
        SELECT user_id
        FROM session_user
        WHERE session_id = ?
    `, sessionID).Scan(&userID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", logger.LogErr(fmt.Errorf("%w: %s", ErrSessionUserNotFound, sessionID))
		}
		return "", logger.LogErr(fmt.Errorf("query session user %s: %w", sessionID, err))
	}

	if strings.TrimSpace(userID) == "" {
		return "", logger.LogErr(fmt.Errorf("%w: %s", ErrSessionUserNotFound, sessionID))
	}

	return userID, nil
}

func (s *Store) deleteAccessTokenByID(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        DELETE FROM access_token
        WHERE id = ?
    `, id)
	if err != nil {
		return logger.LogErr(fmt.Errorf("delete access token %s: %w", id, err))
	}
	return nil
}

func (s *Store) deleteRefreshTokenByID(ctx context.Context, id string) error {
	if strings.TrimSpace(id) == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        DELETE FROM refresh_token
        WHERE id = ?
    `, id)
	if err != nil {
		return logger.LogErr(fmt.Errorf("delete refresh token %s: %w", id, err))
	}
	return nil
}
