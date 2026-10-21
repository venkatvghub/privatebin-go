package config

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	good := Config{DeleteSalt: strings.Repeat("s", 32)}
	cases := []struct {
		name string
		mod  func(*Config)
		want string // substring of the error; empty means valid
	}{
		{"ok", func(*Config) {}, ""},
		{"short salt", func(c *Config) { c.DeleteSalt = "x" }, "DELETE_SALT"},
		{"placeholder salt", func(c *Config) { c.DeleteSalt = "change-me-generate-with-openssl-rand-hex-32" }, "DELETE_SALT"},
		{"bad prefix", func(c *Config) { c.TablePrefix = `a"; drop table paste;--` }, "TABLE_PREFIX"},
		{"auth missing", func(c *Config) { c.AuthEnabled = true }, "OIDC_ISSUER"},
		{"auth short secret", func(c *Config) {
			c.AuthEnabled, c.OIDCIssuer, c.OIDCClientID, c.SessionSecret = true, "i", "c", "short"
		}, "SESSION_SECRET"},
	}
	for _, tc := range cases {
		c := good
		tc.mod(&c)
		err := c.validate()
		switch {
		case tc.want == "" && err != nil:
			t.Errorf("%s: unexpected error %v", tc.name, err)
		case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}
