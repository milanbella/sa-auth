package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/milanbella/sa-auth/logger"
)

type authorizationRequest struct {
	ResponseType    string
	ClientID        string
	RedirectURI     *url.URL
	RawRedirectURI  string
	Scope           []string
	State           string
	OriginalRequest *http.Request
}

type authorizationError struct {
	Code        string
	Description string
	Cause       error
}

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

func processHTTPAuthorizationRequest(r *http.Request) (*authorizationRequest, error) {
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

	authReq := &authorizationRequest{
		ResponseType:    responseType,
		ClientID:        clientID,
		RedirectURI:     redirectURI,
		RawRedirectURI:  rawRedirectURI,
		Scope:           scopes,
		State:           state,
		OriginalRequest: r,
	}

	return authReq, nil
}
