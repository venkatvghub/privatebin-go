package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
	"github.com/venkatvghub/privatebin-go/internal/config"
	"golang.org/x/oauth2"
)

// The login flow cookie must be gone after every callback outcome, not only
// after a successful login.
func TestCallbackAlwaysClearsFlowCookie(t *testing.T) {
	gin.SetMode(gin.TestMode)
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer idp.Close()

	key := bytes.Repeat([]byte("k"), 32)
	a := &Auth{
		cfg:     &config.Config{BaseURL: "http://localhost"},
		oauth:   oauth2.Config{ClientID: "c", Endpoint: oauth2.Endpoint{TokenURL: idp.URL}},
		session: securecookie.New(key, nil).MaxAge(int(sessionTTL.Seconds())),
		flow:    securecookie.New(key, nil).MaxAge(int(flowTTL.Seconds())),
	}
	valid, err := a.flow.Encode(flowCookie, flow{State: "s", Nonce: "n", Verifier: "v"})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, cookie, query string
		want                int
	}{
		{"no cookie", "", "state=s&code=x", http.StatusBadRequest},
		{"forged cookie", flowCookie + "=garbage", "state=s&code=x", http.StatusBadRequest},
		{"state mismatch", flowCookie + "=" + valid, "state=other&code=x", http.StatusBadRequest},
		{"token exchange fails", flowCookie + "=" + valid, "state=s&code=x", http.StatusBadGateway},
	}
	r := gin.New()
	r.GET("/auth/callback", a.callback)
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?"+c.query, nil)
		if c.cookie != "" {
			req.Header.Set("Cookie", c.cookie)
		}
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
		cleared := false
		for _, sc := range rec.Header().Values("Set-Cookie") {
			if strings.HasPrefix(sc, flowCookie+"=;") && strings.Contains(sc, "Max-Age=0") {
				cleared = true
			}
		}
		if !cleared {
			t.Errorf("%s: flow cookie not cleared: %v", c.name, rec.Header().Values("Set-Cookie"))
		}
	}
}
