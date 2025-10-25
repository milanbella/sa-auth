package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/milanbella/sa-auth/logger"
)

// ErrInvalidCredentials indicates the supplied username/password combination is invalid.
var ErrInvalidCredentials = errors.New("invalid credentials")

// Login authenticates a user and binds the provided session to the user.
// It returns the authenticated user's ID when successful.
func Login(ctx context.Context, store *Store, sessionID, usernameOrEmail, password string) (string, error) {
	if store == nil {
		return "", logger.LogErr(errors.New("auth store is nil"))
	}
	if strings.TrimSpace(sessionID) == "" {
		return "", logger.LogErr(errors.New("session id is required"))
	}
	usernameOrEmail = strings.TrimSpace(usernameOrEmail)
	if usernameOrEmail == "" {
		return "", logger.LogErr(errors.New("username or email is required"))
	}
	if password == "" {
		return "", logger.LogErr(errors.New("password is required"))
	}

	userID, hashedPassword, err := store.findUserCredentials(ctx, usernameOrEmail)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return "", err
		}
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	if err := store.rebindSessionUser(ctx, sessionID, userID); err != nil {
		return "", err
	}

	return userID, nil
}

func (s *Store) findUserCredentials(ctx context.Context, usernameOrEmail string) (string, string, error) {
	var (
		userID string
		hash   string
	)

	err := s.db.QueryRowContext(ctx, `
		SELECT id, password_hash
		FROM user
		WHERE username = ?
	`, usernameOrEmail).Scan(&userID, &hash)
	switch {
	case err == nil:
		return userID, hash, nil
	case errors.Is(err, sql.ErrNoRows):
		err = s.db.QueryRowContext(ctx, `
			SELECT id, password_hash
			FROM user
			WHERE email = ?
		`, usernameOrEmail).Scan(&userID, &hash)
		if errors.Is(err, sql.ErrNoRows) {
			return "", "", ErrInvalidCredentials
		}
		if err != nil {
			return "", "", logger.LogErr(fmt.Errorf("query user by email: %w", err))
		}
		return userID, hash, nil
	default:
		return "", "", logger.LogErr(fmt.Errorf("query user by username: %w", err))
	}
}

func (s *Store) rebindSessionUser(ctx context.Context, sessionID, userID string) error {
	if _, err := s.db.ExecContext(ctx, `
		DELETE FROM session_user
		WHERE session_id = ?
	`, sessionID); err != nil {
		return logger.LogErr(fmt.Errorf("delete session_user for session %s: %w", sessionID, err))
	}

	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO session_user (session_id, user_id)
		VALUES (?, ?)
	`, sessionID, userID); err != nil {
		return logger.LogErr(fmt.Errorf("insert session_user for session %s: %w", sessionID, err))
	}

	return nil
}
