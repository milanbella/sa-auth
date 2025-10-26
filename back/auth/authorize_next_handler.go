package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/milanbella/sa-auth/logger"
)

type AuthorizationNextHandler struct {
	store     *Store
	loginPath string
}

func NewAuthorizationNextHandler(store *Store, loginPath string) http.Handler {
	return &AuthorizationNextHandler{
		store:     store,
		loginPath: loginPath,
	}
}

func (h *AuthorizationNextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx, err := processAuthorizationNextRequest(r, h.store)
	if err != nil {
		var nextErr *authorizationNextError
		if errors.As(err, &nextErr) {
			if nextErr.Status == http.StatusMethodNotAllowed {
				w.Header().Set("Allow", http.MethodPost)
			}
			http.Error(w, nextErr.Error(), nextErr.Status)
			return
		}

		logger.Error(fmt.Errorf("process authorization next request: %w", err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	response := ResponseAuthorizationNext{
		GrantType: ctx.GrantType,
	}

	if ctx.NextSecurityTool == nil {
		codeGrant, err := h.store.GetAuthorizationCodeBySession(r.Context(), ctx.Session.ID)
		if err != nil {
			logger.Error(fmt.Errorf("load authorization code for session %s: %w", ctx.Session.ID, err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		if codeGrant.Code == nil || *codeGrant.Code == "" {
			logger.Error(fmt.Errorf("authorization code missing for session %s", ctx.Session.ID))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		redirectURI, err := url.Parse(codeGrant.RedirectURI)
		if err != nil {
			logger.Error(fmt.Errorf("stored redirect URI invalid for session %s: %w", ctx.Session.ID, err))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		successRedirect := cloneURL(redirectURI)
		if successRedirect == nil {
			logger.Error(fmt.Errorf("clone redirect URI failed for session %s", ctx.Session.ID))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		query := successRedirect.Query()
		if codeGrant.Code != nil {
			query.Set("code", *codeGrant.Code)
		}
		if codeGrant.State != "" {
			query.Set("state", codeGrant.State)
		}
		successRedirect.RawQuery = query.Encode()

		response.Completed = true
		response.RedirectURL = successRedirect.String()
	} else {
		tool := *ctx.NextSecurityTool
		response.NextSecurityTool = &tool

		switch tool {
		case SecurityToolLoginForm:
			response.RedirectURL = h.loginPath
		default:
			logger.Error(fmt.Errorf("unsupported next security tool %q for session %s", tool, ctx.Session.ID))
			http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error(fmt.Errorf("encode authorization next response: %w", err))
	}
}
