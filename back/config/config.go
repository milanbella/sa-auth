package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/milanbella/sa-auth/logger"
)

const (
    defaultDBHost            = "127.0.0.1"
    defaultDBPort            = 3306
    defaultDBUser            = "sa_auth"
    defaultDBPassword        = ""
    defaultDBName            = "sa_auth"
    defaultDBMaxOpenConns    = 10
    defaultDBMaxIdleConns    = 5
    defaultDBConnMaxLifetime = time.Minute * 15
    defaultDBPingTimeout     = 5 * time.Second

    defaultAuthLoginPath     = "/login"
    defaultAccessTokenTTL    = 5 * time.Minute
    defaultRefreshTokenTTL   = 24 * time.Hour
)

type Config struct {
	Database DBConfig
	Auth     AuthConfig
}

type DBConfig struct {
	Host            string
	Port            int
	User            string
	Password        string
	Name            string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxLifetime time.Duration
	PingTimeout     time.Duration
}

type AuthConfig struct {
    LoginPath        string
    AccessTokenTTL   time.Duration
    RefreshTokenTTL  time.Duration
}

func Load() (*Config, error) {
	dbCfg, err := loadDBConfigFromEnv()
	if err != nil {
		return nil, logger.LogErr(err)
	}

	authCfg, err := loadAuthConfigFromEnv()
	if err != nil {
		return nil, logger.LogErr(err)
	}

	return &Config{
		Database: *dbCfg,
		Auth:     *authCfg,
	}, nil
}

func loadDBConfigFromEnv() (*DBConfig, error) {
	port, err := getEnvAsInt("DB_PORT", defaultDBPort)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("invalid DB_PORT: %w", err))
	}

	maxOpenConns, err := getEnvAsInt("DB_MAX_OPEN_CONNS", defaultDBMaxOpenConns)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("invalid DB_MAX_OPEN_CONNS: %w", err))
	}

	maxIdleConns, err := getEnvAsInt("DB_MAX_IDLE_CONNS", defaultDBMaxIdleConns)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("invalid DB_MAX_IDLE_CONNS: %w", err))
	}

	connMaxLifetime, err := getEnvAsDuration("DB_CONN_MAX_LIFETIME", defaultDBConnMaxLifetime)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("invalid DB_CONN_MAX_LIFETIME: %w", err))
	}

	pingTimeout, err := getEnvAsDuration("DB_PING_TIMEOUT", defaultDBPingTimeout)
	if err != nil {
		return nil, logger.LogErr(fmt.Errorf("invalid DB_PING_TIMEOUT: %w", err))
	}

	if port <= 0 || port > 65535 {
		return nil, logger.LogErr(fmt.Errorf("DB_PORT must be between 1 and 65535"))
	}

	if maxOpenConns <= 0 {
		return nil, logger.LogErr(fmt.Errorf("DB_MAX_OPEN_CONNS must be greater than zero"))
	}

	if maxIdleConns < 0 {
		return nil, logger.LogErr(fmt.Errorf("DB_MAX_IDLE_CONNS must be zero or a positive integer"))
	}

	if connMaxLifetime < 0 {
		return nil, logger.LogErr(fmt.Errorf("DB_CONN_MAX_LIFETIME must be zero or a positive duration"))
	}

	if pingTimeout <= 0 {
		return nil, logger.LogErr(fmt.Errorf("DB_PING_TIMEOUT must be greater than zero"))
	}

	return &DBConfig{
		Host:            getEnvOrDefault("DB_HOST", defaultDBHost),
		Port:            port,
		User:            getEnvOrDefault("DB_USER", defaultDBUser),
		Password:        getEnvOrDefault("DB_PASSWORD", defaultDBPassword),
		Name:            getEnvOrDefault("DB_NAME", defaultDBName),
		MaxOpenConns:    maxOpenConns,
		MaxIdleConns:    maxIdleConns,
		ConnMaxLifetime: connMaxLifetime,
		PingTimeout:     pingTimeout,
	}, nil
}

func loadAuthConfigFromEnv() (*AuthConfig, error) {
    loginPath := getEnvOrDefault("AUTH_LOGIN_PATH", defaultAuthLoginPath)
    loginPath = strings.TrimSpace(loginPath)
    if loginPath == "" {
        return nil, logger.LogErr(fmt.Errorf("AUTH_LOGIN_PATH must not be empty"))
    }
    if strings.HasPrefix(loginPath, "http://") || strings.HasPrefix(loginPath, "https://") {
        return nil, logger.LogErr(fmt.Errorf("AUTH_LOGIN_PATH must be relative"))
    }
    if !strings.HasPrefix(loginPath, "/") {
        loginPath = "/" + loginPath
    }

    accessTTL, err := getEnvAsDuration("AUTH_ACCESS_TOKEN_TTL", defaultAccessTokenTTL)
    if err != nil {
        return nil, logger.LogErr(fmt.Errorf("invalid AUTH_ACCESS_TOKEN_TTL: %w", err))
    }
    if accessTTL <= 0 {
        return nil, logger.LogErr(fmt.Errorf("AUTH_ACCESS_TOKEN_TTL must be greater than zero"))
    }

    refreshTTL, err := getEnvAsDuration("AUTH_REFRESH_TOKEN_TTL", defaultRefreshTokenTTL)
    if err != nil {
        return nil, logger.LogErr(fmt.Errorf("invalid AUTH_REFRESH_TOKEN_TTL: %w", err))
    }
    if refreshTTL <= 0 {
        return nil, logger.LogErr(fmt.Errorf("AUTH_REFRESH_TOKEN_TTL must be greater than zero"))
    }

    return &AuthConfig{
        LoginPath:       loginPath,
        AccessTokenTTL:  accessTTL,
        RefreshTokenTTL: refreshTTL,
    }, nil
}

func getEnvOrDefault(key string, defaultValue string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) (int, error) {
	valueStr, ok := os.LookupEnv(key)
	if !ok || valueStr == "" {
		return defaultValue, nil
	}

	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return 0, logger.LogErr(err)
	}

	return value, nil
}

func getEnvAsDuration(key string, defaultValue time.Duration) (time.Duration, error) {
	valueStr, ok := os.LookupEnv(key)
	if !ok || valueStr == "" {
		return defaultValue, nil
	}

	value, err := time.ParseDuration(valueStr)
	if err != nil {
		return 0, logger.LogErr(err)
	}

	return value, nil
}
