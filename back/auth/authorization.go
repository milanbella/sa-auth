package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/session"
	"github.com/milanbella/sa-auth/stringutils"
)

type authorizationRequest struct {
	ResponseType    string
	ClientID        string
	RedirectURI     *url.URL
	RawRedirectURI  string
	Scope           []string
	State           string
	OriginalRequest *http.Request
	Client          *Client
	Session         session.Info
	Code            *AuthorizationCode
}

type authorizationError struct {
	Code        string
	Description string
	Cause       error
	RedirectURI *url.URL
	State       string
}

var (
	// ErrClientNotFound is returned when a client with the provided identifier does not exist.
	ErrClientNotFound = errors.New("client not found")
	// ErrAuthorizationCodeNotFound is returned when no authorization code exists for the session.
	ErrAuthorizationCodeNotFound = errors.New("authorization code not found")
)

func (e *authorizationError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Description)
	}
	return e.Code
}

func (e *authorizationError) Unwrap() error {
	return e.Cause
}

func newAuthorizationError(code, description string, cause error) error {
	return &authorizationError{
		Code:        code,
		Description: description,
		Cause:       cause,
	}
}

const authorizationCodeTTL = 10 * time.Minute

func processHTTPAuthorizationRequest(r *http.Request, store *Store) (*authorizationRequest, error) {
	if store == nil {
		return nil, logger.LogErr(newAuthorizationError("server_error", "authorization service misconfigured", errors.New("nil store")))
	}

	sessionInfo, ok := session.FromContext(r.Context())
	if !ok || sessionInfo.ID == "" {
		return nil, logger.LogErr(newAuthorizationError("server_error", "session not available", errors.New("missing session")))
	}

	if r.Method != http.MethodGet {
		return nil, logger.LogErr(newAuthorizationError("invalid_request", "authorization request must use GET", errors.New("invalid_method")))
	}

	if err := r.ParseForm(); err != nil {
		return nil, logger.LogErr(newAuthorizationError("invalid_request", "unable to parse request parameters", err))
	}

	responseType := r.Form.Get("response_type")
	if responseType == "" {
		return nil, logger.LogErr(newAuthorizationError("invalid_request", "response_type is required", nil))
	}
	if responseType != "code" {
		return nil, logger.LogErr(newAuthorizationError("unsupported_response_type", "response_type must be \"code\"", nil))
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return nil, logger.LogErr(newAuthorizationError("invalid_request", "client_id is required", nil))
	}

	rawRedirectURI := r.Form.Get("redirect_uri")
	var redirectURI *url.URL
	if rawRedirectURI != "" {
		parsedURI, err := url.Parse(rawRedirectURI)
		if err != nil {
			return nil, logger.LogErr(newAuthorizationError("invalid_request", "redirect_uri is malformed", err))
		}
		if !parsedURI.IsAbs() {
			return nil, logger.LogErr(newAuthorizationError("invalid_request", "redirect_uri must be absolute", errors.New("invalid_redirect_uri")))
		}
		redirectURI = parsedURI
	}

	scopeParam := r.Form.Get("scope")
	var scopes []string
	if scopeParam != "" {
		scopes = strings.Fields(scopeParam)
	}

	state := r.Form.Get("state")

	client, err := store.GetClientByClientID(r.Context(), clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			return nil, logger.LogErr(newAuthorizationError("unauthorized_client", "client not registered", err))
		}
		return nil, logger.LogErr(newAuthorizationError("server_error", "unable to load client", err))
	}

	var registeredRedirect *url.URL
	if client.RedirectURI != "" {
		registeredRedirect, err = url.Parse(client.RedirectURI)
		if err != nil {
			return nil, logger.LogErr(newAuthorizationError("server_error", "client redirect_uri misconfigured", fmt.Errorf("invalid registered redirect uri: %w", err)))
		}
		if !registeredRedirect.IsAbs() {
			return nil, logger.LogErr(newAuthorizationError("server_error", "client redirect_uri misconfigured", errors.New("registered redirect uri is not absolute")))
		}
	}

	var validatedRedirect *url.URL
	if redirectURI != nil {
		if registeredRedirect != nil && !urlsEqual(registeredRedirect, redirectURI) {
			authErr := newAuthorizationError("invalid_request", "redirect_uri does not match registered value", errors.New("redirect_uri_mismatch")).(*authorizationError)
			return nil, logger.LogErr(authErr)
		}
		validatedRedirect = redirectURI
	} else {
		if registeredRedirect == nil {
			return nil, logger.LogErr(newAuthorizationError("invalid_request", "redirect_uri is required", errors.New("redirect_uri_missing")))
		}
		validatedRedirect = registeredRedirect
	}

	expiresAt := time.Now().UTC().Add(authorizationCodeTTL)
	nextTool := SecurityToolLoginForm

	authCode := &AuthorizationCode{
		SessionID:        sessionInfo.ID,
		ClientID:         client.ID,
		State:            state,
		Scope:            scopes,
		RedirectURI:      validatedRedirect.String(),
		ExpiresAt:        expiresAt,
		NextSecurityTool: &nextTool,
		GrantType:        GrantTypeAuthorizationCode,
	}

	if err := store.SaveAuthorizationCode(r.Context(), authCode); err != nil {
		authErr := newAuthorizationError("server_error", "unable to persist authorization request", err).(*authorizationError)
		authErr.RedirectURI = cloneURL(validatedRedirect)
		authErr.State = state
		return nil, logger.LogErr(authErr)
	}

	authReq := &authorizationRequest{
		ResponseType:    responseType,
		ClientID:        clientID,
		RedirectURI:     validatedRedirect,
		RawRedirectURI:  rawRedirectURI,
		Scope:           scopes,
		State:           state,
		OriginalRequest: r,
		Client:          client,
		Session:         sessionInfo,
		Code:            authCode,
	}

	return authReq, nil
}

func urlsEqual(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	return a.String() == b.String()
}

func cloneURL(in *url.URL) *url.URL {
	if in == nil {
		return nil
	}

	u := *in
	return &u
}

// GetClientByClientID returns the client registered with the provided client_id.
func (s *Store) GetClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, client_id, client_secret, name, redirect_uri, created_at, updated_at
		FROM client
		WHERE client_id = ?
	`, clientID)

	var client Client

	if err := row.Scan(
		&client.ID,
		&client.ClientID,
		&client.ClientSecret,
		&client.Name,
		&client.RedirectURI,
		&client.CreatedAt,
		&client.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, logger.LogErr(fmt.Errorf("get client %s: %w", clientID, err))
	}

	return &client, nil
}

// SaveAuthorizationCode persists the provided authorization code grant.
func (s *Store) SaveAuthorizationCode(ctx context.Context, code *AuthorizationCode) error {
	if code == nil {
		return logger.LogErr(errors.New("authorization code is nil"))
	}

	scope := strings.Join(code.Scope, " ")
	var state sql.NullString
	if code.State != "" {
		state = sql.NullString{String: code.State, Valid: true}
	}

	var codeValue interface{}
	if code.Code != nil {
		trimmed := strings.TrimSpace(*code.Code)
		if trimmed != "" {
			codeValue = trimmed
			if *code.Code != trimmed {
				*code.Code = trimmed
			}
		}
	}

	var nextTool interface{}
	if code.NextSecurityTool != nil {
		nextTool = string(*code.NextSecurityTool)
	}

	var grantType interface{}
	if code.GrantType != "" {
		grantType = string(code.GrantType)
	}

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM code_grant
		WHERE session_id = ?
	`, code.SessionID); err != nil {
		return logger.LogErr(fmt.Errorf("delete existing code grant for session %s: %w", code.SessionID, err))
	}

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO code_grant (
			session_id,
			client_id,
			code,
			state,
			scope,
			redirect_uri,
			next_security_tool,
			expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		code.SessionID,
		code.ClientID,
		codeValue,
		state,
		stringutils.NullIfBlank(scope),
		code.RedirectURI,
		nextTool,
		code.ExpiresAt,
	)
	if err != nil {
		return logger.LogErr(fmt.Errorf("insert code grant for session %s: %w", code.SessionID, err))
	}

	if _, err := s.db.ExecContext(ctx, `
		UPDATE session
		SET next_security_tool = ?, grant_type = COALESCE(?, grant_type)
		WHERE id = ?
	`, nextTool, grantType, code.SessionID); err != nil {
		return logger.LogErr(fmt.Errorf("update session authorization state for session %s: %w", code.SessionID, err))
	}
	return nil
}

// GetAuthorizationCodeBySession returns the authorization code record associated with the session.
func (s *Store) GetAuthorizationCodeBySession(ctx context.Context, sessionID string) (*AuthorizationCode, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT client_id, code, state, scope, redirect_uri, next_security_tool, expires_at
		FROM code_grant
		WHERE session_id = ?
	`, sessionID)

	var (
		clientID    string
		codeValue   sql.NullString
		stateVal    sql.NullString
		scopeVal    sql.NullString
		redirectURI string
		nextToolVal sql.NullString
		expiresAt   time.Time
	)

	if err := row.Scan(&clientID, &codeValue, &stateVal, &scopeVal, &redirectURI, &nextToolVal, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthorizationCodeNotFound
		}
		return nil, logger.LogErr(fmt.Errorf("get code grant for session %s: %w", sessionID, err))
	}

	var scopes []string
	if scopeVal.Valid && strings.TrimSpace(scopeVal.String) != "" {
		scopes = strings.Fields(scopeVal.String)
	}

	var codePtr *string
	if codeValue.Valid {
		v := codeValue.String
		codePtr = &v
	}

	authCode := &AuthorizationCode{
		SessionID:   sessionID,
		ClientID:    clientID,
		Code:        codePtr,
		State:       stateVal.String,
		Scope:       scopes,
		RedirectURI: redirectURI,
		ExpiresAt:   expiresAt,
	}

	if nextToolVal.Valid {
		tool := SecurityTool(nextToolVal.String)
		authCode.NextSecurityTool = &tool
	}

	return authCode, nil
}

// GetAuthorizationCodeByCode fetches the authorization code record matching the provided code.
func (s *Store) GetAuthorizationCodeByCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	code = strings.TrimSpace(code)
	if code == "" {
		return nil, logger.LogErr(errors.New("authorization code is required"))
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT session_id, client_id, code, state, scope, redirect_uri, next_security_tool, expires_at
		FROM code_grant
		WHERE code = ?
	`, code)

	var (
		sessionID   string
		clientID    string
		codeValue   sql.NullString
		stateVal    sql.NullString
		scopeVal    sql.NullString
		redirectURI string
		nextToolVal sql.NullString
		expiresAt   time.Time
	)

	if err := row.Scan(&sessionID, &clientID, &codeValue, &stateVal, &scopeVal, &redirectURI, &nextToolVal, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrAuthorizationCodeNotFound
		}
		return nil, logger.LogErr(fmt.Errorf("get code grant by code %s: %w", code, err))
	}

	var scopes []string
	if scopeVal.Valid && strings.TrimSpace(scopeVal.String) != "" {
		scopes = strings.Fields(scopeVal.String)
	}

	authCode := &AuthorizationCode{
		SessionID:   sessionID,
		ClientID:    clientID,
		State:       stateVal.String,
		Scope:       scopes,
		RedirectURI: redirectURI,
		ExpiresAt:   expiresAt,
	}
	if codeValue.Valid {
		value := codeValue.String
		authCode.Code = &value
	}
	if nextToolVal.Valid {
		tool := SecurityTool(nextToolVal.String)
		authCode.NextSecurityTool = &tool
	}

	return authCode, nil
}

// DeleteAuthorizationCode removes the authorization code entry associated with the session.
func (s *Store) DeleteAuthorizationCode(ctx context.Context, sessionID string) error {
	if strings.TrimSpace(sessionID) == "" {
		return logger.LogErr(errors.New("session id is required to delete authorization code"))
	}

	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM code_grant
		WHERE session_id = ?
	`, sessionID); err != nil {
		return logger.LogErr(fmt.Errorf("delete code grant for session %s: %w", sessionID, err))
	}

	return nil
}
