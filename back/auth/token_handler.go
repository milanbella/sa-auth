package auth

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/milanbella/sa-auth/logger"
)

// TokenHandler handles OAuth token endpoint requests.
type TokenHandler struct {
	store      *Store
	accessTTL  time.Duration
	refreshTTL time.Duration
}

// NewTokenHandler constructs an http.Handler for the token endpoint.
func NewTokenHandler(store *Store, accessTTL, refreshTTL time.Duration) http.Handler {
	return &TokenHandler{
		store:      store,
		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		logger.Error(errors.New("token handler misconfigured: nil store"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	result, err := processTokenRequest(r, h.store, h.accessTTL, h.refreshTTL)
	if err != nil {
		h.handleError(w, err)
		return
	}

	if result == nil || result.AccessToken == nil {
		logger.Error(errors.New("token handler received empty token result"))
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	scope := strings.Join(result.Scope, " ")
	refreshTokenValue := ""
	if result.RefreshToken != nil {
		refreshTokenValue = result.RefreshToken.Token
	}

	expiresIn := int64(result.AccessToken.ExpiresAt.Sub(time.Now().UTC()).Seconds())
	if expiresIn < 0 {
		expiresIn = 0
	}

	response := struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int64  `json:"expires_in"`
		RefreshToken string `json:"refresh_token,omitempty"`
		Scope        string `json:"scope,omitempty"`
	}{
		AccessToken:  result.AccessToken.Token,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshTokenValue,
	}

	if scope != "" {
		response.Scope = scope
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error(err)
	}
}

func (h *TokenHandler) handleError(w http.ResponseWriter, err error) {
	var tErr *tokenError
	if errors.As(err, &tErr) && tErr != nil {
		status := tErr.status
		if status == 0 {
			status = http.StatusBadRequest
		}
		if tErr.wwwAuthenticate {
			w.Header().Set("WWW-Authenticate", `Basic realm="sa-auth", error="`+tErr.code+`"`)
		}

		response := map[string]string{
			"error": tErr.code,
		}
		if tErr.description != "" {
			response["error_description"] = tErr.description
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			logger.Error(err)
		}
		return
	}

	logger.Error(err)
	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}
