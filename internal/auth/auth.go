// Package auth wires optional OIDC (Dex) login. Login only gates paste
// creation; nothing about the user is stored with a paste.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/venkatvghub/privatebin-go/internal/config"
	"golang.org/x/oauth2"
)

const (
	sessionCookie = "pbgo_session"
	flowCookie    = "pbgo_oidc"
	sessionTTL    = 12 * time.Hour
	flowTTL       = 10 * time.Minute
)

// flow is the login state kept in a short-lived signed cookie.
type flow struct{ State, Nonce, Verifier string }

type Auth struct {
	cfg      *config.Config
	oauth    oauth2.Config
	verifier *oidc.IDTokenVerifier
	session  *securecookie.SecureCookie // signed, expiring "logged in" marker
	flow     *securecookie.SecureCookie // signed, expiring login state
}

func New(ctx context.Context, cfg *config.Config) (*Auth, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(ctx, cfg.OIDCIssuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	key := []byte(cfg.SessionSecret)
	return &Auth{
		cfg:     cfg,
		session: securecookie.New(key, nil).MaxAge(int(sessionTTL.Seconds())),
		flow:    securecookie.New(key, nil).MaxAge(int(flowTTL.Seconds())),
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

func (a *Auth) setCookie(c *gin.Context, name, val string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: val, Path: "/", MaxAge: int(ttl.Seconds()),
		HttpOnly: true, Secure: strings.HasPrefix(a.cfg.BaseURL, "https://"), SameSite: http.SameSiteLaxMode,
	})
}

// LoggedIn reports whether the request carries a valid session.
func (a *Auth) LoggedIn(c *gin.Context) bool {
	ck, err := c.Cookie(sessionCookie)
	if err != nil {
		return false
	}
	var v string
	return a.session.Decode(sessionCookie, ck, &v) == nil && v == "1"
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
	f := flow{State: oauth2.GenerateVerifier(), Nonce: oauth2.GenerateVerifier(), Verifier: oauth2.GenerateVerifier()}
	enc, err := a.flow.Encode(flowCookie, f)
	if err != nil {
		c.String(http.StatusInternalServerError, "login unavailable")
		return
	}
	a.setCookie(c, flowCookie, enc, flowTTL)
	c.Redirect(http.StatusFound, a.oauth.AuthCodeURL(f.State, oidc.Nonce(f.Nonce), oauth2.S256ChallengeOption(f.Verifier)))
}

func (a *Auth) callback(c *gin.Context) {
	raw, _ := c.Cookie(flowCookie)
	// The flow cookie is single use: drop it whatever the outcome, so a failed
	// attempt cannot leave a stale one behind to confuse the next try.
	a.setCookie(c, flowCookie, "", -time.Second)
	var f flow
	if a.flow.Decode(flowCookie, raw, &f) != nil || c.Query("state") != f.State {
		c.String(http.StatusBadRequest, "invalid login state")
		return
	}
	tok, err := a.oauth.Exchange(c.Request.Context(), c.Query("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		c.String(http.StatusBadGateway, "token exchange failed")
		return
	}
	rawID, _ := tok.Extra("id_token").(string)
	id, err := a.verifier.Verify(c.Request.Context(), rawID)
	if err != nil || id.Nonce != f.Nonce {
		c.String(http.StatusUnauthorized, "invalid id token")
		return
	}
	enc, err := a.session.Encode(sessionCookie, "1")
	if err != nil {
		c.String(http.StatusInternalServerError, "login unavailable")
		return
	}
	a.setCookie(c, sessionCookie, enc, sessionTTL)
	c.Redirect(http.StatusFound, "/")
}
