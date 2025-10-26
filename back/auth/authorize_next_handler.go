package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"
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

	switch ctx.GrantType {
	case GrantTypeAuthorizationCode:
		h.handleAuthorizationCodeGrant(w, r, ctx, response)
	default:
		logger.Error(fmt.Errorf("unsupported grant type %q for session %s", ctx.GrantType, ctx.Session.ID))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *AuthorizationNextHandler) handleAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, ctx *authorizationNextContext, response ResponseAuthorizationNext) {
	if ctx.NextSecurityTool == nil {
		h.completeAuthorizationCodeGrant(w, r, ctx, response)
		return
	}

	tool := *ctx.NextSecurityTool
	response.NextSecurityTool = &tool

	switch tool {
	case SecurityToolLoginForm:
		response.RedirectURL = h.loginPath
		writeAuthorizationNextResponse(w, response)
	default:
		logger.Error(fmt.Errorf("unsupported next security tool %q for session %s", tool, ctx.Session.ID))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}
}

func (h *AuthorizationNextHandler) completeAuthorizationCodeGrant(w http.ResponseWriter, r *http.Request, ctx *authorizationNextContext, response ResponseAuthorizationNext) {
	codeGrant, err := h.store.GetAuthorizationCodeBySession(r.Context(), ctx.Session.ID)
	if err != nil {
		logger.Error(fmt.Errorf("load authorization code for session %s: %w", ctx.Session.ID, err))
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

	newCode := uuid.NewString()
	expiresAt := time.Now().UTC().Add(authorizationCodeTTL)
	codeGrant.Code = &newCode
	codeGrant.ExpiresAt = expiresAt
	codeGrant.GrantType = ctx.GrantType
	codeGrant.NextSecurityTool = nil

	if err := h.store.SaveAuthorizationCode(r.Context(), codeGrant); err != nil {
		logger.Error(fmt.Errorf("complete authorization code grant for session %s: %w", ctx.Session.ID, err))
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
	writeAuthorizationNextResponse(w, response)
}

func writeAuthorizationNextResponse(w http.ResponseWriter, response ResponseAuthorizationNext) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error(fmt.Errorf("encode authorization next response: %w", err))
	}
}
