package session

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type ctxKey string

const (
	cookieName               = "sa_session"
	sessionContextKey ctxKey = "session-token"

	rotationInterval = 15 * time.Minute
	sessionTTL       = 24 * time.Hour
)

// Manager ensures every request has a valid session cookie and keeps the session fresh.
type Manager struct {
	db *sql.DB
}

func NewManager(db *sql.DB) *Manager {
	return &Manager{db: db}
}

// Middleware sets or refreshes the session cookie as needed before calling the next handler.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()

		token, cookieToSet, err := m.ensureSession(ctx, r.Cookie)
		if err != nil {
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if cookieToSet != nil {
			http.SetCookie(w, cookieToSet)
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, sessionContextKey, token)))
	})
}

func (m *Manager) ensureSession(ctx context.Context, cookieFn func(name string) (*http.Cookie, error)) (string, *http.Cookie, error) {
	cookie, err := cookieFn(cookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return m.createSession(ctx)
		}
		return "", nil, err
	}

	if cookie.Value == "" {
		return m.createSession(ctx)
	}

	sessionToken := cookie.Value
	row := m.db.QueryRowContext(ctx, `
		SELECT id, expires_at, updated_at
		FROM session
		WHERE session_token = ?
	`, sessionToken)

	var (
		id        string
		expiresAt time.Time
		updatedAt time.Time
	)
	if err := row.Scan(&id, &expiresAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return m.createSession(ctx)
		}
		return "", nil, err
	}

	now := time.Now().UTC()
	if now.After(expiresAt) {
		return m.replaceSession(ctx, id)
	}

	if now.Sub(updatedAt) >= rotationInterval {
		return m.rotateSession(ctx, id)
	}

	return sessionToken, nil, nil
}

func (m *Manager) createSession(ctx context.Context) (string, *http.Cookie, error) {
	sessionID := uuid.NewString()
	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(sessionTTL)

	_, err := m.db.ExecContext(ctx, `
		INSERT INTO session (id, session_token, expires_at)
		VALUES (?, ?, ?)
	`, sessionID, sessionToken, expiresAt)
	if err != nil {
		return "", nil, err
	}

	return sessionToken, buildCookie(sessionToken, expiresAt), nil
}

func (m *Manager) rotateSession(ctx context.Context, id string) (string, *http.Cookie, error) {
	sessionToken := uuid.NewString()
	expiresAt := time.Now().UTC().Add(sessionTTL)

	res, err := m.db.ExecContext(ctx, `
		UPDATE session
		SET session_token = ?, expires_at = ?
		WHERE id = ?
	`, sessionToken, expiresAt, id)
	if err != nil {
		return "", nil, err
	}

	if affected, _ := res.RowsAffected(); affected == 0 {
		return m.createSession(ctx)
	}

	return sessionToken, buildCookie(sessionToken, expiresAt), nil
}

func (m *Manager) replaceSession(ctx context.Context, id string) (string, *http.Cookie, error) {
	if _, err := m.db.ExecContext(ctx, `DELETE FROM session WHERE id = ?`, id); err != nil {
		return "", nil, err
	}
	return m.createSession(ctx)
}

func buildCookie(token string, expiresAt time.Time) *http.Cookie {
	return &http.Cookie{
		Name:     cookieName,
		Value:    token,
		HttpOnly: true,
		Path:     "/",
		Expires:  expiresAt,
		SameSite: http.SameSiteLaxMode,
	}
}

// FromContext extracts the session token stored by the middleware.
func FromContext(ctx context.Context) (string, bool) {
	val, ok := ctx.Value(sessionContextKey).(string)
	return val, ok
}
