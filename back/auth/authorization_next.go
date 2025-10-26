package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/session"
)

type authorizationNextContext struct {
	Session          session.Info
	GrantType        GrantType
	NextSecurityTool *SecurityTool
	Request          RequestAuthorizationNext
}

type authorizationNextError struct {
	Status  int
	Message string
	Err     error
}

func (e *authorizationNextError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return http.StatusText(e.Status)
}

func (e *authorizationNextError) Unwrap() error {
	return e.Err
}

func processAuthorizationNextRequest(r *http.Request, store *Store) (*authorizationNextContext, error) {
	if store == nil {
		return nil, &authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     errors.New("authorization next handler misconfigured: nil store"),
		}
	}

	if r.Method != http.MethodPost {
		return nil, &authorizationNextError{
			Status:  http.StatusMethodNotAllowed,
			Message: "method not allowed",
			Err:     fmt.Errorf("invalid method %s", r.Method),
		}
	}

	contentType := r.Header.Get("Content-Type")
	if contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		return nil, &authorizationNextError{
			Status:  http.StatusUnsupportedMediaType,
			Message: "content type must be application/json",
			Err:     fmt.Errorf("unsupported content type %s", contentType),
		}
	}

	var payload RequestAuthorizationNext
	if r.Body != nil {
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			if !errors.Is(err, io.EOF) {
				return nil, &authorizationNextError{
					Status:  http.StatusBadRequest,
					Message: "invalid json payload",
					Err:     err,
				}
			}
		}
		// Ensure there is no additional data.
		if err := decoder.Decode(&struct{}{}); err != nil && !errors.Is(err, io.EOF) {
			return nil, &authorizationNextError{
				Status:  http.StatusBadRequest,
				Message: "invalid json payload",
				Err:     err,
			}
		}
	}

	sessionInfo, ok := session.FromContext(r.Context())
	if !ok || sessionInfo.ID == "" {
		return nil, &authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     errors.New("session information missing in context"),
		}
	}

	grantType, nextTool, err := store.GetSessionAuthorizationState(r.Context(), sessionInfo.ID)
	if err != nil {
		return nil, err
	}

	if grantType == "" {
		return nil, &authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     fmt.Errorf("grant type not set for session %s", sessionInfo.ID),
		}
	}

	return &authorizationNextContext{
		Session:          sessionInfo,
		GrantType:        grantType,
		NextSecurityTool: nextTool,
		Request:          payload,
	}, nil
}

func (s *Store) GetSessionAuthorizationState(ctx context.Context, sessionID string) (GrantType, *SecurityTool, error) {
	if strings.TrimSpace(sessionID) == "" {
		return "", nil, logger.LogErr(&authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     errors.New("session id is required"),
		})
	}

	row := s.db.QueryRowContext(ctx, `
		SELECT grant_type, next_security_tool
		FROM session
		WHERE id = ?
	`, sessionID)

	var (
		grantTypeVal sql.NullString
		nextToolVal  sql.NullString
	)

	if err := row.Scan(&grantTypeVal, &nextToolVal); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", nil, logger.LogErr(&authorizationNextError{
				Status:  http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
				Err:     fmt.Errorf("session %s not found", sessionID),
			})
		}
		return "", nil, logger.LogErr(&authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     fmt.Errorf("query session %s: %w", sessionID, err),
		})
	}

	if !grantTypeVal.Valid || strings.TrimSpace(grantTypeVal.String) == "" {
		return "", nil, logger.LogErr(&authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     fmt.Errorf("grant type missing for session %s", sessionID),
		})
	}

	grantType := GrantType(grantTypeVal.String)
	if !isSupportedGrantType(grantType) {
		return "", nil, logger.LogErr(&authorizationNextError{
			Status:  http.StatusInternalServerError,
			Message: http.StatusText(http.StatusInternalServerError),
			Err:     fmt.Errorf("unsupported grant type %q for session %s", grantType, sessionID),
		})
	}

	var nextTool *SecurityTool
	if nextToolVal.Valid && strings.TrimSpace(nextToolVal.String) != "" {
		tool := SecurityTool(nextToolVal.String)
		if !isSupportedSecurityTool(tool) {
			return "", nil, logger.LogErr(&authorizationNextError{
				Status:  http.StatusInternalServerError,
				Message: http.StatusText(http.StatusInternalServerError),
				Err:     fmt.Errorf("unsupported security tool %q for session %s", tool, sessionID),
			})
		}
		nextTool = &tool
	}

	return grantType, nextTool, nil
}

func isSupportedGrantType(gt GrantType) bool {
	switch gt {
	case GrantTypeAuthorizationCode:
		return true
	default:
		return false
	}
}

func isSupportedSecurityTool(tool SecurityTool) bool {
	switch tool {
	case SecurityToolLoginForm:
		return true
	default:
		return false
	}
}
