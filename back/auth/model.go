package auth

import "time"

type SecurityTool string

const (
	SecurityToolLoginForm SecurityTool = "LOGIN_FORM"
)

// Client represents an OAuth client application registered with the authorization server.
type Client struct {
	ID           string
	ClientID     string
	ClientSecret string
	Name         string
	RedirectURI  string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AuthorizationCode encapsulates a persisted authorization code grant.
type AuthorizationCode struct {
	SessionID        string
	ClientID         string
	Code             *string
	State            string
	Scope            []string
	RedirectURI      string
	ExpiresAt        time.Time
	NextSecurityTool *SecurityTool
}

// AccessToken represents an issued bearer token.
type AccessToken struct {
	ID        string
	Token     string
	SessionID string
	ClientID  string
	UserID    string
	Scope     []string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// RefreshToken represents a long-lived refresh credential.
type RefreshToken struct {
	ID        string
	Token     string
	SessionID string
	ClientID  string
	UserID    string
	Scope     []string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}
