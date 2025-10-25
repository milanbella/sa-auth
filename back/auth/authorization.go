package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/session"
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
	ResponseURI     *url.URL
}

type authorizationError struct {
	Code        string
	Description string
	Cause       error
	RedirectURI *url.URL
	State       string
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

	codeValue := uuid.NewString()
	expiresAt := time.Now().UTC().Add(authorizationCodeTTL)

	authCode := &AuthorizationCode{
		SessionID:   sessionInfo.ID,
		ClientID:    client.ID,
		Code:        codeValue,
		State:       state,
		Scope:       scopes,
		RedirectURI: validatedRedirect.String(),
		ExpiresAt:   expiresAt,
	}

	if err := store.SaveAuthorizationCode(r.Context(), authCode); err != nil {
		authErr := newAuthorizationError("server_error", "unable to persist authorization code", err).(*authorizationError)
		authErr.RedirectURI = cloneURL(validatedRedirect)
		authErr.State = state
		return nil, logger.LogErr(authErr)
	}

	redirectForResponse := cloneURL(validatedRedirect)
	query := redirectForResponse.Query()
	query.Set("code", authCode.Code)
	if state != "" {
		query.Set("state", state)
	}
	redirectForResponse.RawQuery = query.Encode()

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
		ResponseURI:     redirectForResponse,
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
