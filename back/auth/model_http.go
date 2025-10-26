package auth

type RequestAuthorizationNext struct{}

type ResponseAuthorizationNext struct {
	GrantType        GrantType     `json:"grant_type"`
	NextSecurityTool *SecurityTool `json:"next_security_tool,omitempty"`
	RedirectURL      string        `json:"redirect_url,omitempty"`
	Completed        bool          `json:"completed"`
}

type RequestLogin struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type ResponseLogin struct {
	RedirectURL string `json:"redirect_url,omitempty"`
	Message     string `json:"message,omitempty"`
}
