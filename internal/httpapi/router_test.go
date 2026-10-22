package httpapi

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/venkatvghub/privatebin-go/internal/config"
	"github.com/venkatvghub/privatebin-go/internal/obs"
	"github.com/venkatvghub/privatebin-go/internal/paste"
	"github.com/venkatvghub/privatebin-go/internal/testdb"
	"github.com/venkatvghub/privatebin-go/web"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const reqBody = `{"v":2,"adata":[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,%d],"ct":"AAAA","meta":{"expire":"5min"}}`

func newTestRouter(t *testing.T, mods ...func(*config.Config)) http.Handler {
	t.Helper()
	db, err := gorm.Open(postgres.Open(testdb.DSN(t)), &gorm.Config{NamingStrategy: paste.NamingStrategy("")})
	if err != nil {
		t.Fatal(err)
	}
	svc := paste.New(db, strings.Repeat("s", 32))
	if err := svc.Migrate(""); err != nil {
		t.Fatal(err)
	}
	page := web.IndexData{Name: "privatebin-go"}
	index, err := web.RenderIndex(page)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{MaxPasteBytes: 1 << 20, MetricsEnabled: true}
	for _, mod := range mods {
		mod(cfg)
	}
	return NewRouter(Deps{
		Log: zap.NewNop(), Metrics: obs.NewMetrics(), DB: db, Paste: svc, Static: web.FS(), Index: index, Page: page, Cfg: cfg,
	})
}

func do(h http.Handler, method, target, body string, json bool) map[string]any {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if json {
		req.Header.Set("X-Requested-With", "JSONHttpRequest")
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := map[string]any{}
	_ = jsonDecode(rec.Body.Bytes(), &out)
	out["_code"] = float64(rec.Code)
	return out
}

func jsonDecode(b []byte, v any) error { return json.Unmarshal(b, v) }

func TestPrivateBinRoundTrip(t *testing.T) {
	h := newTestRouter(t)
	created := do(h, "POST", "/", strings.Replace(reqBody, "%d", "0", 1), true)
	if created["status"] != float64(0) {
		t.Fatalf("create: %v", created)
	}
	id, tok := created["id"].(string), created["deletetoken"].(string)
	if created["url"] != "?"+id || len(tok) != 64 {
		t.Fatalf("unexpected create response: %v", created)
	}

	for _, target := range []string{"/?" + id, "/?pasteid=" + id} {
		got := do(h, "GET", target, "", true)
		if got["status"] != float64(0) || got["ct"] != "AAAA" || got["v"] != float64(2) {
			t.Fatalf("read %s: %v", target, got)
		}
		if _, ok := got["meta"].(map[string]any)["time_to_live"]; !ok {
			t.Fatalf("missing time_to_live: %v", got["meta"])
		}
	}

	if got := do(h, "GET", "/?pasteid="+id+"&deletetoken=bad", "", true); got["status"] != float64(1) ||
		got["message"] != msgWrongToken || got["_code"] != float64(200) {
		t.Fatalf("bad token: %v", got)
	}
	if got := do(h, "GET", "/?pasteid="+id+"&deletetoken="+tok, "", true); got["status"] != float64(0) {
		t.Fatalf("delete: %v", got)
	}
	if got := do(h, "GET", "/?"+id, "", true); got["status"] != float64(1) || got["message"] != msgNotFound {
		t.Fatalf("read after delete: %v", got)
	}
}

func TestBurnAfterReading(t *testing.T) {
	h := newTestRouter(t)
	created := do(h, "POST", "/", strings.Replace(reqBody, "%d", "1", 1), true)
	id := created["id"].(string)
	if first := do(h, "GET", "/?"+id, "", true); first["status"] != float64(0) {
		t.Fatalf("first read: %v", first)
	}
	if second := do(h, "GET", "/?"+id, "", true); second["status"] != float64(1) {
		t.Fatalf("second read should fail: %v", second)
	}
}

func TestRejects(t *testing.T) {
	h := newTestRouter(t)
	for name, body := range map[string]string{
		"wrong version": `{"v":1}`,
		"comment":       `{"pasteid":"0123456789abcdef","parentid":"0123456789abcdef","v":2}`,
		"not json":      `nope`,
	} {
		if got := do(h, "POST", "/", body, true); got["status"] != float64(1) {
			t.Errorf("%s: %v", name, got)
		}
	}
	// Every route taking a paste id validates its shape before touching the database.
	for _, target := range []string{"/?not-an-id", "/?pasteid=short"} {
		if got := do(h, "GET", target, "", target[:2] == "/?"); got["status"] != float64(1) || got["message"] != msgInvalid {
			t.Errorf("%s: want %q, got %v", target, msgInvalid, got)
		}
	}
	if got := do(h, "POST", "/", strings.Replace(reqBody, "%d", "0", 1), false); got["status"] != float64(1) {
		t.Errorf("POST without JSON header must be rejected: %v", got)
	}
}

func TestMetricsOnAppPort(t *testing.T) {
	h := newTestRouter(t)
	created := do(h, "POST", "/", strings.Replace(reqBody, "%d", "0", 1), true)
	id := created["id"].(string)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	body := rec.Body.String()
	if rec.Code != 200 {
		t.Fatalf("GET /metrics: %d", rec.Code)
	}
	for _, want := range []string{
		`privatebin_go_http_requests_total{method="POST",route="/",status="200"}`,
		`privatebin_go_pastes_created_total{burn="false"} 1`,
		"go_goroutines",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(body, id) || strings.Contains(body, created["deletetoken"].(string)) {
		t.Error("metrics must never carry a paste id or delete token")
	}
}

func TestMetricsCanBeDisabled(t *testing.T) {
	h := newTestRouter(t, func(c *config.Config) { c.MetricsEnabled = false })
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if rec.Code != 404 {
		t.Fatalf("GET /metrics with metrics disabled: %d, want 404", rec.Code)
	}
}

// The PrivateBin interface needs these from the server: its page at "/", the
// wasm module served as application/wasm, and a CSP that lets it run.
func TestInterfaceIsServed(t *testing.T) {
	h := newTestRouter(t)
	get := func(path string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec
	}
	page := get("/")
	if page.Code != 200 || !strings.Contains(page.Body.String(), `id="pasteExpiration"`) {
		t.Fatalf("GET /: %d", page.Code)
	}
	csp := page.Header().Get("Content-Security-Policy")
	for _, want := range []string{"script-src 'self' 'wasm-unsafe-eval'", "frame-ancestors 'none'", "style-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP lacks %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("the page must not allow inline code: %s", csp)
	}
	for path, wantType := range map[string]string{
		"/js/zlib-1.3.2.wasm":            "application/wasm",
		"/js/privatebin.js":              "javascript",
		"/css/bootstrap5/privatebin.css": "text/css",
		"/img/bootstrap-icons.svg":       "image/svg+xml",
		"/i18n/de.json":                  "json",
		"/manifest.json":                 "json",
	} {
		rec := get(path)
		if rec.Code != 200 || !strings.Contains(rec.Header().Get("Content-Type"), wantType) {
			t.Errorf("%s: %d %q, want a %q type", path, rec.Code, rec.Header().Get("Content-Type"), wantType)
		}
		if rec.Header().Get("Cache-Control") == "" {
			t.Errorf("%s: no Cache-Control", path)
		}
	}
	if rec := get("/nope.js"); rec.Code != 404 {
		t.Errorf("missing file: %d, want 404", rec.Code)
	}
}

// PrivateBin's delete link is opened as a page: the server deletes, then shows
// the interface with a confirmation or the reason it failed.
func TestDeleteLinkPage(t *testing.T) {
	h := newTestRouter(t)
	page := func(path string) string {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		if rec.Code != 200 {
			t.Fatalf("GET %s: %d", path, rec.Code)
		}
		// The URL of this page carries the delete token: it must not leak through
		// Referer, nor be cached.
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Errorf("GET %s: Referrer-Policy %q, want no-referrer", path, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s: Cache-Control %q, want no-store", path, got)
		}
		return rec.Body.String()
	}
	created := do(h, "POST", "/", strings.Replace(reqBody, "%d", "0", 1), true)
	id, tok := created["id"].(string), created["deletetoken"].(string)

	if body := page("/?pasteid=" + id + "&deletetoken=wrong"); !strings.Contains(body, msgWrongToken) || strings.Contains(body, "new-from-alert") {
		t.Error("a wrong token must show the error and keep the paste")
	}
	if got := do(h, "GET", "/?"+id, "", true); got["status"] != float64(0) {
		t.Fatalf("paste must survive a wrong token: %v", got)
	}
	if body := page("/?pasteid=" + id + "&deletetoken=" + tok); !strings.Contains(body, "Document was properly deleted.") || !strings.Contains(body, `id="new-from-alert"`) {
		t.Error("the right token must delete and confirm")
	}
	if got := do(h, "GET", "/?"+id, "", true); got["status"] != float64(1) {
		t.Fatalf("paste must be gone: %v", got)
	}
	if body := page("/?pasteid=" + id + "&deletetoken=" + tok); !strings.Contains(body, msgNotFound) {
		t.Error("deleting again must report that the document does not exist")
	}
}

// The wording is a compatibility contract with PrivateBin 2.1.0. PrivateBin's
// translation table (copied unmodified into web/i18n, sums pinned) is keyed by
// the exact English message, so a message that is not a key there is not one
// PrivateBin 2.1.0 sends, and the interface could not translate it.
func TestMessagesAreKnownToPrivateBin(t *testing.T) {
	raw, err := fs.ReadFile(web.FS(), "i18n/de.json")
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage // values are strings, or arrays for plurals
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	for name, msg := range map[string]string{
		"msgNotFound":     msgNotFound,
		"msgInvalid":      msgInvalid,
		"msgWrongToken":   msgWrongToken,
		"msgDeleted":      msgDeleted,
		"msgSizeLimitFmt": msgSizeLimitFmt,
		"msgRateLimitFmt": msgRateLimitFmt,
	} {
		if _, ok := keys[msg]; !ok {
			t.Errorf("%s = %q is not a PrivateBin 2.1.0 message", name, msg)
		}
	}
	// The size-limit message is built in the handler: check what a client sees.
	h := newTestRouter(t, func(c *config.Config) { c.MaxPasteBytes = 1 << 10 })
	big := strings.Replace(reqBody, `"ct":"AAAA"`, `"ct":"`+strings.Repeat("A", 4096)+`"`, 1)
	big = strings.Replace(big, "%d", "0", 1)
	if got := do(h, "POST", "/", big, true); got["message"] != fmt.Sprintf(msgSizeLimitFmt, "1.00 KiB") {
		t.Errorf("size limit message: %v", got)
	}
}
