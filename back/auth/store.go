package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/stringutils"
)

var (
	// ErrClientNotFound is returned when a client with the provided identifier does not exist.
	ErrClientNotFound = errors.New("client not found")
)

// Store provides database-backed operations needed by authorization flows.
type Store struct {
	db *sql.DB
}

// NewStore constructs a Store backed by the given sql.DB.
func NewStore(db *sql.DB) *Store {
	return &Store{db: db}
}

// GetClientByClientID returns the client registered with the provided client_id.
func (s *Store) GetClientByClientID(ctx context.Context, clientID string) (*Client, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, client_id, client_secret, name, redirect_uri, created_at, updated_at
		FROM client
		WHERE client_id = ?
	`, clientID)

	var (
		client Client
	)

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

	_, err := s.db.ExecContext(ctx, `
		INSERT INTO code_grant (
			id,
			session_id,
			client_id,
			code,
			state,
			scope,
			redirect_uri,
			expires_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`,
		code.ID,
		code.SessionID,
		code.ClientID,
		code.Code,
		state,
		stringutils.NullIfBlank(scope),
		code.RedirectURI,
		code.ExpiresAt,
	)
	if err != nil {
		return logger.LogErr(fmt.Errorf("insert code grant %s: %w", code.ID, err))
	}
	return nil
}
