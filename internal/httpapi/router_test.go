package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/venkatvghub/privatebin-go/internal/config"
	"github.com/venkatvghub/privatebin-go/internal/obs"
	"github.com/venkatvghub/privatebin-go/internal/paste"
	"github.com/venkatvghub/privatebin-go/internal/testdb"
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
	static := fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}
	cfg := &config.Config{MaxPasteBytes: 1 << 20, MetricsEnabled: true}
	for _, mod := range mods {
		mod(cfg)
	}
	return NewRouter(Deps{
		Log: zap.NewNop(), Metrics: obs.NewMetrics(), DB: db, Paste: svc, Static: static, Cfg: cfg,
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
	if got := do(h, "GET", "/api/paste/"+id+"/meta", "", false); got["burn"] != true {
		t.Fatalf("meta: %v", got)
	}
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
	for _, target := range []string{"/?not-an-id", "/?pasteid=short", "/api/paste/not-an-id/meta"} {
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
