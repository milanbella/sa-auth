package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

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

	var (
		username string
		password string
	)

	contentType := r.Header.Get("Content-Type")
	if strings.HasPrefix(contentType, "application/json") {
		var payload RequestLogin
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			writeJSONResponse(w, http.StatusBadRequest, ResponseLogin{
				Message: "invalid json payload",
			})
			return
		}
		username = payload.Username
		password = payload.Password
	} else {
		if err := r.ParseForm(); err != nil {
			writeJSONResponse(w, http.StatusBadRequest, ResponseLogin{
				Message: "invalid form data",
			})
			return
		}
		username = r.Form.Get("username")
		password = r.Form.Get("password")
	}

	username = strings.TrimSpace(username)
	if username == "" || password == "" {
		writeJSONResponse(w, http.StatusBadRequest, ResponseLogin{
			Message: "username and password are required",
		})
		return
	}

	sessionInfo, ok := session.FromContext(r.Context())
	if !ok || sessionInfo.ID == "" {
		logger.Error(errors.New("session information missing in context"))
		writeJSONResponse(w, http.StatusInternalServerError, ResponseLogin{
			Message: http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	if _, err := h.store.GetAuthorizationCodeBySession(r.Context(), sessionInfo.ID); err != nil {
		if errors.Is(err, ErrAuthorizationCodeNotFound) {
			writeJSONResponse(w, http.StatusBadRequest, ResponseLogin{
				Message: "authorization request not found",
			})
			return
		}
		logger.Error(fmt.Errorf("load authorization code for session %s: %w", sessionInfo.ID, err))
		writeJSONResponse(w, http.StatusInternalServerError, ResponseLogin{
			Message: http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	if _, err := Login(r.Context(), h.store, sessionInfo.ID, username, password); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			writeJSONResponse(w, http.StatusUnauthorized, ResponseLogin{
				Message: "invalid credentials",
			})
			return
		}
		logger.Error(fmt.Errorf("login failed for session %s: %w", sessionInfo.ID, err))
		writeJSONResponse(w, http.StatusInternalServerError, ResponseLogin{
			Message: http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	if err := h.store.SetSessionNextSecurityTool(r.Context(), sessionInfo.ID, nil); err != nil {
		logger.Error(fmt.Errorf("clear next security tool for session %s: %w", sessionInfo.ID, err))
		writeJSONResponse(w, http.StatusInternalServerError, ResponseLogin{
			Message: http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	w.Header().Set("Location", "/auth/authorize/next")
	writeJSONResponse(w, http.StatusOK, ResponseLogin{
		RedirectURL: "/auth/authorize/next",
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, payload ResponseLogin) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.Error(fmt.Errorf("write login response: %w", err))
	}
}
