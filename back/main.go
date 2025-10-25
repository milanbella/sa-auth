package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/milanbella/sa-auth/auth"
	"github.com/milanbella/sa-auth/config"
	"github.com/milanbella/sa-auth/db"
	"github.com/milanbella/sa-auth/logger"
	"github.com/milanbella/sa-auth/session"
)

func main() {
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal(fmt.Errorf("load config: %w", err))
	}

	sqlDB, err := db.New(ctx, cfg.Database)
	if err != nil {
		logger.Fatal(fmt.Errorf("init db: %w", err))
	}
	defer func() {
		if err := sqlDB.Close(); err != nil {
			logger.LogErr(fmt.Errorf("close db: %w", err))
		}
	}()

	sessionManager := session.NewManager(sqlDB)
	authStore := auth.NewStore(sqlDB)

	router := newRouter(sessionManager, authStore, cfg.Auth.LoginPath, cfg.Auth.AccessTokenTTL, cfg.Auth.RefreshTokenTTL)

	log.Println("listening on :8080")
	if err := http.ListenAndServe(":8080", router); err != nil {
		logger.Fatal(fmt.Errorf("http server failed: %w", err))
	}
}

func newRouter(sessionManager *session.Manager, authStore *auth.Store, loginPath string, accessTTL, refreshTTL time.Duration) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/hello", getHelloHandler)
	mux.HandleFunc("/auth/hello", auth.HelloHandler)
	mux.Handle("/auth/authorize", auth.NewAuthorizationHandler(authStore, loginPath))
	mux.Handle("/auth/login", auth.NewLoginHandler(authStore))
	mux.Handle("/auth/token", auth.NewTokenHandler(authStore, accessTTL, refreshTTL))

	return sessionManager.Middleware(mux)
}

func getHelloHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	_, _ = w.Write([]byte("Hello!"))
}
