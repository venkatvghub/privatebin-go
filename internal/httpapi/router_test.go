package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/venkatvghub/privatebin-go/internal/config"
	"github.com/venkatvghub/privatebin-go/internal/obs"
	"github.com/venkatvghub/privatebin-go/internal/paste"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

const reqBody = `{"v":2,"adata":[["AAAAAAAAAAAAAAAA","AAAAAAAAAAA=",100000,256,128,"aes","gcm","none"],"plaintext",0,%d],"ct":"AAAA","meta":{"expire":"5min"}}`

func newTestRouter(t *testing.T) http.Handler {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{NamingStrategy: paste.NamingStrategy("")})
	if err != nil {
		t.Fatal(err)
	}
	svc := paste.New(db, strings.Repeat("s", 32))
	if err := svc.Migrate(""); err != nil {
		t.Fatal(err)
	}
	static := fstest.MapFS{"index.html": {Data: []byte("<html></html>")}}
	return NewRouter(Deps{
		Log: zap.NewNop(), Metrics: obs.NewMetrics(), DB: db, Paste: svc, Static: static,
		Cfg: &config.Config{MaxPasteBytes: 1 << 20},
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
	if got := do(h, "POST", "/", strings.Replace(reqBody, "%d", "0", 1), false); got["status"] != float64(1) {
		t.Errorf("POST without JSON header must be rejected: %v", got)
	}
}
