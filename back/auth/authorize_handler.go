package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/milanbella/sa-auth/logger"
)

// AuthorizationHandler handles OAuth 2.0 authorization requests.
type AuthorizationHandler struct {
	store     *Store
	loginPath string
}

// NewAuthorizationHandler constructs an http.Handler that processes authorization requests.
func NewAuthorizationHandler(store *Store, loginPath string) http.Handler {
	return &AuthorizationHandler{store: store, loginPath: loginPath}
}

func (h *AuthorizationHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		logger.Error(errors.New("authorization handler misconfigured: nil store"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	if h.loginPath == "" {
		logger.Error(errors.New("authorization handler misconfigured: empty login path"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	authReq, err := processHTTPAuthorizationRequest(r, h.store)
	if err != nil {
		h.handleError(w, r, err)
		return
	}

	codeGrant, err := h.store.GetAuthorizationCodeBySession(r.Context(), authReq.Session.ID)
	if err != nil {
		if errors.Is(err, ErrAuthorizationCodeNotFound) {
			logger.Error(fmt.Errorf("authorization code missing for session %s", authReq.Session.ID))
		} else {
			logger.Error(fmt.Errorf("load authorization request for session %s: %w", authReq.Session.ID, err))
		}
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	switch {
	case codeGrant.NextSecurityTool == nil:
		logger.Error(fmt.Errorf("next security tool not set for session %s", authReq.Session.ID))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	case *codeGrant.NextSecurityTool == SecurityToolLoginForm:
		http.Redirect(w, r, h.loginPath, http.StatusFound)
	default:
		logger.Error(fmt.Errorf("unsupported next security tool %q for session %s", *codeGrant.NextSecurityTool, authReq.Session.ID))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *AuthorizationHandler) handleError(w http.ResponseWriter, r *http.Request, err error) {
	var authErr *authorizationError
	if errors.As(err, &authErr) && authErr != nil {
		if authErr.RedirectURI != nil {
			redirect := appendErrorQuery(authErr.RedirectURI, authErr.Code, authErr.Description, authErr.State)
			http.Redirect(w, r, redirect.String(), http.StatusFound)
			return
		}

		status := http.StatusBadRequest
		if authErr.Code == "server_error" {
			status = http.StatusInternalServerError
		}
		http.Error(w, authErr.Error(), status)
		return
	}

	logger.Error(err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func appendErrorQuery(base *url.URL, code, description, state string) *url.URL {
	redirect := cloneURL(base)
	if redirect == nil {
		return base
	}

	query := redirect.Query()
	query.Set("error", code)
	if description != "" {
		query.Set("error_description", description)
	}
	if state != "" {
		query.Set("state", state)
	}
	redirect.RawQuery = query.Encode()

	return redirect
}
