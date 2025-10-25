package auth

import "time"

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
	SessionID   string
	ClientID    string
	Code        *string
	State       string
	Scope       []string
	RedirectURI string
	ExpiresAt   time.Time
}
