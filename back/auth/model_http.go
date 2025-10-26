package auth

type RequestAuthorizationNext struct{}

type ResponseAuthorizationNext struct {
	GrantType        GrantType     `json:"grant_type"`
	NextSecurityTool *SecurityTool `json:"next_security_tool,omitempty"`
	RedirectURL      string        `json:"redirect_url,omitempty"`
	Completed        bool          `json:"completed"`
}
