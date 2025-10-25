package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
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
