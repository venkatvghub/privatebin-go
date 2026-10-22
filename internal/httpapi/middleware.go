package httpapi

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/venkatvghub/privatebin-go/internal/obs"
	"go.uber.org/zap"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"
)

// baseCSP is PrivateBin 2.1.0's default policy (the interface is built for it:
// lib/Configuration.php, 'cspheader'), identical except that connect-src is
// narrowed from * to this origin, since the app only talks to itself. 2.1.0's
// sandbox has no allow-popups and its base-uri is 'self'; TestCSPMatchesPrivateBin210
// pins all of it.
const baseCSP = "default-src 'none'; base-uri 'self'; form-action 'none'; manifest-src 'self'; connect-src 'self' blob:; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; font-src 'self'; frame-ancestors 'none'; frame-src blob:; img-src 'self' data: blob:; media-src blob:; object-src blob:; sandbox allow-same-origin allow-scripts allow-forms allow-modals allow-downloads"

func securityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("Content-Security-Policy", baseCSP)
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		c.Next()
	}
}

// swaggerCSP relaxes style-src for swagger-ui, which injects inline styles.
func swaggerCSP() gin.HandlerFunc {
	csp := strings.Replace(baseCSP, "style-src 'self'", "style-src 'self' 'unsafe-inline'", 1)
	return func(c *gin.Context) {
		c.Writer.Header().Set("Content-Security-Policy", csp)
		c.Next()
	}
}

func bodyLimit(n int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, n)
		c.Next()
	}
}

const (
	limiterIdleTTL   = 10 * time.Minute
	limiterSweepLen  = 1024 // start evicting idle entries once the map is this big
	limiterSweepStep = 32   // entries examined per request, so the lock is held O(1)
)

type visitor struct {
	lim  *rate.Limiter
	seen time.Time
}

// ipLimiter is a per-IP token bucket (rate tokens/sec, burst b). Idle entries
// are evicted individually, so active clients never get a fresh burst.
type ipLimiter struct {
	mu    sync.Mutex
	m     map[string]*visitor
	rate  rate.Limit
	burst int
}

func (l *ipLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.m) > limiterSweepLen {
		l.sweep(now)
	}
	v, ok := l.m[ip]
	if !ok {
		v = &visitor{lim: rate.NewLimiter(l.rate, l.burst)}
		l.m[ip] = v
	}
	v.seen = now
	return v.lim.Allow()
}

// sweep examines at most limiterSweepStep entries. Go starts map iteration at a
// random entry, so repeated bounded sweeps reach every entry over time while a
// single request never scans the whole map under the lock.
func (l *ipLimiter) sweep(now time.Time) {
	n := 0
	for k, v := range l.m {
		if now.Sub(v.seen) > limiterIdleTTL {
			delete(l.m, k)
		}
		if n++; n >= limiterSweepStep {
			return
		}
	}
}

func newLimiter(r rate.Limit, b int) gin.HandlerFunc {
	l := &ipLimiter{m: map[string]*visitor{}, rate: r, burst: b}
	return func(c *gin.Context) {
		if !l.allow(c.ClientIP(), time.Now()) {
			fail(c, fmt.Sprintf(msgRateLimitFmt, 1))
			return
		}
		c.Next()
	}
}

// setStaticCache lets browsers reuse an embedded asset. Assets carry no
// validators, so expiry is time based: libraries for a day, our own files for
// an hour.
func setStaticCache(c *gin.Context) {
	age := 3600
	if strings.HasPrefix(c.Request.URL.Path, "/vendor/") {
		age = 86400
	}
	c.Header("Cache-Control", "public, max-age="+strconv.Itoa(age))
}

// observe logs one JSON line per request and records metrics. It logs the
// route template only: no query string (holds delete tokens), no IP, no body.
func observe(log *zap.Logger, m *obs.Metrics) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		route := c.FullPath()
		if route == "" {
			route = "unmatched"
		}
		status := c.Writer.Status()
		d := time.Since(start)
		m.Requests.WithLabelValues(c.Request.Method, route, strconv.Itoa(status)).Inc()
		m.Latency.WithLabelValues(c.Request.Method, route).Observe(d.Seconds())
		f := []zap.Field{zap.String("method", c.Request.Method), zap.String("route", route),
			zap.Int("status", status), zap.Duration("duration", d), zap.Int("bytes", max(c.Writer.Size(), 0))}
		if status >= 500 {
			log.Error("request", f...)
		} else {
			log.Info("request", f...)
		}
	}
}

func recoverer(log *zap.Logger) gin.HandlerFunc {
	return gin.CustomRecoveryWithWriter(nil, func(c *gin.Context, v any) {
		log.Error("panic", zap.Any("panic", v))
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"status": 1, "message": "internal error"})
	})
}
