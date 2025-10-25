package auth

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/session"
)

// LoginHandler handles resource owner credential submission and returns the authorization code.
type LoginHandler struct {
	store *Store
}

// NewLoginHandler constructs an http.Handler for login requests.
func NewLoginHandler(store *Store) http.Handler {
	return &LoginHandler{store: store}
}

func (h *LoginHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		logger.Error(errors.New("login handler misconfigured: nil store"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}

	sessionInfo, ok := session.FromContext(r.Context())
	if !ok || sessionInfo.ID == "" {
		logger.Error(errors.New("session information missing in context"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	authorizationCode, err := h.store.GetAuthorizationCodeBySession(r.Context(), sessionInfo.ID)
	if err != nil {
		if errors.Is(err, ErrAuthorizationCodeNotFound) {
			http.Error(w, "authorization request not found", http.StatusBadRequest)
			return
		}
		logger.Error(fmt.Errorf("load authorization code for session %s: %w", sessionInfo.ID, err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	redirectURI, err := url.Parse(authorizationCode.RedirectURI)
	if err != nil {
		logger.Error(fmt.Errorf("stored redirect URI invalid for session %s: %w", sessionInfo.ID, err))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	username := r.Form.Get("username")
	password := r.Form.Get("password")

	if _, err := Login(r.Context(), h.store, sessionInfo.ID, username, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			errorRedirect := appendErrorQuery(redirectURI, "access_denied", "invalid credentials", authorizationCode.State)
			http.Redirect(w, r, errorRedirect.String(), http.StatusFound)
			return
		}
		logger.Error(fmt.Errorf("login failed for session %s: %w", sessionInfo.ID, err))
		errorRedirect := appendErrorQuery(redirectURI, "server_error", "internal error", authorizationCode.State)
		http.Redirect(w, r, errorRedirect.String(), http.StatusFound)
		return
	}

	newCode := uuid.NewString()
	expiresAt := time.Now().UTC().Add(authorizationCodeTTL)
	rotatedCode := &AuthorizationCode{
		SessionID:   authorizationCode.SessionID,
		ClientID:    authorizationCode.ClientID,
		Code:        &newCode,
		State:       authorizationCode.State,
		Scope:       authorizationCode.Scope,
		RedirectURI: authorizationCode.RedirectURI,
		ExpiresAt:   expiresAt,
	}

	if err := h.store.SaveAuthorizationCode(r.Context(), rotatedCode); err != nil {
		logger.Error(fmt.Errorf("rotate authorization code for session %s: %w", sessionInfo.ID, err))
		errorRedirect := appendErrorQuery(redirectURI, "server_error", "internal error", authorizationCode.State)
		http.Redirect(w, r, errorRedirect.String(), http.StatusFound)
		return
	}

	successRedirect := cloneURL(redirectURI)
	query := successRedirect.Query()
	if rotatedCode.Code != nil {
		query.Set("code", *rotatedCode.Code)
	}
	if authorizationCode.State != "" {
		query.Set("state", authorizationCode.State)
	}
	successRedirect.RawQuery = query.Encode()

	http.Redirect(w, r, successRedirect.String(), http.StatusFound)
}
