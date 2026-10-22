package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
	"github.com/venkatvghub/privatebin-go/web"
)

type Config struct {
	AppName  string `env:"APP_NAME,notEmpty"`
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
	// MetricsEnabled serves Prometheus metrics on the app port at /metrics.
	MetricsEnabled bool `env:"METRICS_ENABLED" envDefault:"true"`

	DatabaseURL string `env:"DATABASE_URL,notEmpty"`
	// TablePrefix is PrivateBin's "tbl" option. It is spliced into DDL, so it is
	// validated to plain identifier characters.
	TablePrefix string `env:"TABLE_PREFIX"`
	// DeleteSalt keys the delete tokens; set equal to PrivateBin's server salt to
	// honour tokens it issued.
	DeleteSalt string `env:"DELETE_SALT,notEmpty"`

	ListenAddr    string `env:"LISTEN_ADDR" envDefault:":8080"`
	BaseURL       string `env:"BASE_URL" envDefault:"http://localhost:8080"`
	MaxPasteBytes int64  `env:"MAX_PASTE_BYTES" envDefault:"2097152"`
	// TrustedProxies lists proxies whose X-Forwarded-For is believed; empty means
	// the client IP is the TCP peer (so the per-IP rate limit cannot be spoofed).
	TrustedProxies []string `env:"TRUSTED_PROXIES" envSeparator:","`
	SwaggerEnabled bool     `env:"SWAGGER_ENABLED" envDefault:"true"`

	// Page: the name in the title, nav and footer; operator text for the footer (HTML,
	// e.g. a link); and an optional prettify theme for source code.
	AppTitle    string `env:"APP_TITLE" envDefault:"privatebin-go"`
	PageInfo    string `env:"PAGE_INFO"`
	SyntaxTheme string `env:"SYNTAX_THEME"`
	// BurnAfterReadingDefault preselects "Burn after reading" in the interface. Users
	// can untick it per paste, because the flag is chosen (and authenticated) by the browser.
	BurnAfterReadingDefault bool `env:"BURN_AFTER_READING_DEFAULT" envDefault:"true"`

	AuthEnabled      bool   `env:"AUTH_ENABLED"`
	OIDCIssuer       string `env:"OIDC_ISSUER"`
	OIDCClientID     string `env:"OIDC_CLIENT_ID"`
	OIDCClientSecret string `env:"OIDC_CLIENT_SECRET"`
	SessionSecret    string `env:"SESSION_SECRET"`
}

const minSecretLen = 32

var prefixRe = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

// Load reads .env (if present; real environment variables win), parses the
// environment and validates the result.
func Load() (*Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load .env: %w", err)
	}
	var c Config
	if err := env.Parse(&c); err != nil {
		return nil, err
	}
	return &c, c.validate()
}

// isPlaceholder spots secrets copied unchanged from .env.example.
func isPlaceholder(s string) bool { return strings.Contains(s, "change-me") }

func (c *Config) validate() error {
	var errs []error
	if !prefixRe.MatchString(c.TablePrefix) {
		errs = append(errs, errors.New("TABLE_PREFIX may only contain letters, digits and underscores"))
	}
	if c.SyntaxTheme != "" && !slices.Contains(web.SyntaxThemes, c.SyntaxTheme) {
		errs = append(errs, fmt.Errorf("SYNTAX_THEME must be empty or one of %v", web.SyntaxThemes))
	}
	if len(c.DeleteSalt) < minSecretLen || isPlaceholder(c.DeleteSalt) {
		errs = append(errs, fmt.Errorf("DELETE_SALT must be a random value of at least %d characters (not the .env.example placeholder)", minSecretLen))
	}
	if c.AuthEnabled {
		if c.OIDCIssuer == "" || c.OIDCClientID == "" {
			errs = append(errs, errors.New("AUTH_ENABLED needs OIDC_ISSUER and OIDC_CLIENT_ID"))
		}
		if len(c.SessionSecret) < minSecretLen || isPlaceholder(c.SessionSecret) {
			errs = append(errs, fmt.Errorf("SESSION_SECRET must be at least %d characters", minSecretLen))
		}
	}
	return errors.Join(errs...)
}
