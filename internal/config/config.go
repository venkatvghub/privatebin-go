package config

import (
	"fmt"
	"os"
	"regexp"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	AppName     string
	TablePrefix string // PrivateBin "tbl" option
	DeleteSalt  string // HMAC key for delete tokens; share with PrivateBin to honour its tokens
	LogLevel    string
	MetricsAddr string // empty disables metrics

	DatabaseURL    string
	ListenAddr     string
	BaseURL        string
	MaxPasteBytes  int64
	CookieSecure   bool
	SwaggerEnabled bool

	AuthEnabled      bool
	OIDCIssuer       string
	OIDCClientID     string
	OIDCClientSecret string
	SessionSecret    string
}

var identRe = regexp.MustCompile(`[^A-Za-z0-9_]+`)

// Load reads .env (if present; real env vars win) then the environment.
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("load .env: %w", err)
	}
	c := &Config{
		AppName:          os.Getenv("APP_NAME"),
		TablePrefix:      os.Getenv("TABLE_PREFIX"),
		DeleteSalt:       os.Getenv("DELETE_SALT"),
		LogLevel:         env("LOG_LEVEL", "info"),
		MetricsAddr:      env("METRICS_ADDR", ":9090"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		ListenAddr:       env("LISTEN_ADDR", ":8080"),
		BaseURL:          env("BASE_URL", "http://localhost:8080"),
		MaxPasteBytes:    envInt("MAX_PASTE_BYTES", 2<<20),
		CookieSecure:     envBool("COOKIE_SECURE", false),
		SwaggerEnabled:   envBool("SWAGGER_ENABLED", true),
		AuthEnabled:      envBool("AUTH_ENABLED", false),
		OIDCIssuer:       os.Getenv("OIDC_ISSUER"),
		OIDCClientID:     os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret: os.Getenv("OIDC_CLIENT_SECRET"),
		SessionSecret:    os.Getenv("SESSION_SECRET"),
	}
	c.TablePrefix = identRe.ReplaceAllString(c.TablePrefix, "")
	if c.AppName == "" {
		return nil, fmt.Errorf("APP_NAME required")
	}
	if len(c.DeleteSalt) < 32 {
		return nil, fmt.Errorf("DELETE_SALT required (>=32 chars)")
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL required")
	}
	if c.AuthEnabled {
		if c.OIDCIssuer == "" || c.OIDCClientID == "" || len(c.SessionSecret) < 32 {
			return nil, fmt.Errorf("AUTH_ENABLED needs OIDC_ISSUER, OIDC_CLIENT_ID, SESSION_SECRET (>=32 chars)")
		}
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int64) int64 {
	if v, err := strconv.ParseInt(os.Getenv(k), 10, 64); err == nil {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v, err := strconv.ParseBool(os.Getenv(k)); err == nil {
		return v
	}
	return def
}
