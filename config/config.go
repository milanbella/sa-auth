package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
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
)

type Config struct {
	Database DBConfig
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

func Load() (*Config, error) {
	dbCfg, err := loadDBConfigFromEnv()
	if err != nil {
		return nil, err
	}

	return &Config{
		Database: *dbCfg,
	}, nil
}

func loadDBConfigFromEnv() (*DBConfig, error) {
	port, err := getEnvAsInt("DB_PORT", defaultDBPort)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PORT: %w", err)
	}

	maxOpenConns, err := getEnvAsInt("DB_MAX_OPEN_CONNS", defaultDBMaxOpenConns)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_OPEN_CONNS: %w", err)
	}

	maxIdleConns, err := getEnvAsInt("DB_MAX_IDLE_CONNS", defaultDBMaxIdleConns)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_MAX_IDLE_CONNS: %w", err)
	}

	connMaxLifetime, err := getEnvAsDuration("DB_CONN_MAX_LIFETIME", defaultDBConnMaxLifetime)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_CONN_MAX_LIFETIME: %w", err)
	}

	pingTimeout, err := getEnvAsDuration("DB_PING_TIMEOUT", defaultDBPingTimeout)
	if err != nil {
		return nil, fmt.Errorf("invalid DB_PING_TIMEOUT: %w", err)
	}

	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("DB_PORT must be between 1 and 65535")
	}

	if maxOpenConns <= 0 {
		return nil, fmt.Errorf("DB_MAX_OPEN_CONNS must be greater than zero")
	}

	if maxIdleConns < 0 {
		return nil, fmt.Errorf("DB_MAX_IDLE_CONNS must be zero or a positive integer")
	}

	if connMaxLifetime < 0 {
		return nil, fmt.Errorf("DB_CONN_MAX_LIFETIME must be zero or a positive duration")
	}

	if pingTimeout <= 0 {
		return nil, fmt.Errorf("DB_PING_TIMEOUT must be greater than zero")
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
		return 0, err
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
		return 0, err
	}

	return value, nil
}
