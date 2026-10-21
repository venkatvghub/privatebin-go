// Package auth wires optional OIDC (Dex) login. Login only gates paste
// creation; nothing about the user is stored with a paste.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/venkatvghub/privatebin-go/internal/config"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "pbgo_session"
	flowCookie    = "pbgo_oidc"
	sessionTTL    = 12 * time.Hour
)

type Auth struct {
	cfg      *config.Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func New(ctx context.Context, cfg *config.Config) (*Auth, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	return &Auth{
		cfg: cfg,
		oauth: oauth2.Config{
			ClientID:     cfg.OIDCClientID,
			ClientSecret: cfg.OIDCClientSecret,
			Endpoint:     p.Endpoint(),
			RedirectURL:  strings.TrimRight(cfg.BaseURL, "/") + "/auth/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		},
		verifier: p.Verifier(&oidc.Config{ClientID: cfg.OIDCClientID}),
	}, nil
}

func (a *Auth) sign(v string) string {
	m := hmac.New(sha256.New, []byte(a.cfg.SessionSecret))
	m.Write([]byte(v))
	return v + "." + base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (a *Auth) unsign(s string) (string, bool) {
	i := strings.LastIndexByte(s, '.')
	if i < 0 {
		return "", false
	}
	if !hmac.Equal([]byte(a.sign(s[:i])), []byte(s)) {
		return "", false
	}
	return s[:i], true
}

func (a *Auth) setCookie(c *gin.Context, name, val string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: val, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: a.cfg.CookieSecure, SameSite: http.SameSiteLaxMode,
	})
}

func rnd() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// LoggedIn reports whether the request carries a valid session.
func (a *Auth) LoggedIn(c *gin.Context) bool {
	ck, err := c.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	v, ok := a.unsign(ck)
	if !ok {
		return false
	}
	exp, err := strconv.ParseInt(v, 10, 64)
	return err == nil && time.Now().Unix() < exp
}

// Require rejects requests without a valid session.
func (a *Auth) Require() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !a.LoggedIn(c) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"status": 1, "message": "Login required."})
			return
		}
		c.Next()
	}
}

func (a *Auth) Routes(r gin.IRoutes) {
	r.GET("/auth/login", a.login)
	r.GET("/auth/callback", a.callback)
	r.POST("/auth/logout", func(c *gin.Context) {
		a.setCookie(c, sessionCookie, "", -time.Second)
		c.Status(http.StatusNoContent)
	})
}

func (a *Auth) login(c *gin.Context) {
	state, nonce, verifier := rnd(), rnd(), oauth2.GenerateVerifier()
	a.setCookie(c, flowCookie, a.sign(state+"|"+nonce+"|"+verifier), 10*time.Minute)
	c.Redirect(http.StatusFound, a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)))
}

func (a *Auth) callback(c *gin.Context) {
	raw, _ := c.Cookie(flowCookie)
	v, ok := a.unsign(raw)
	parts := strings.Split(v, "|")
	if !ok || len(parts) != 3 || c.Query("state") != parts[0] {
		c.String(http.StatusBadRequest, "invalid login state")
		return
	}
	tok, err := a.oauth.Exchange(c.Request.Context(), c.Query("code"), oauth2.VerifierOption(parts[2]))
	if err != nil {
		c.String(http.StatusBadGateway, "token exchange failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	id, err := a.verifier.Verify(c.Request.Context(), rawID)
	if err != nil || id.Nonce != parts[1] {
		c.String(http.StatusUnauthorized, "invalid id token")
		return
	}
	a.setCookie(c, flowCookie, "", -time.Second)
	a.setCookie(c, sessionCookie, a.sign(strconv.FormatInt(time.Now().Add(sessionTTL).Unix(), 10)), sessionTTL)
	c.Redirect(http.StatusFound, "/")
}
