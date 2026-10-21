package httpapi

import (
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

const baseCSP = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

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
	limiterIdleTTL  = 10 * time.Minute
	limiterSweepLen = 1024 // sweep idle entries once the map grows past this
)

type visitor struct {
	lim  *rate.Limiter
	seen time.Time
}

// newLimiter is a per-IP token bucket (r tokens/sec, burst b). Idle entries are
// evicted individually so active clients never get a fresh burst.
func newLimiter(r rate.Limit, b int) gin.HandlerFunc {
	var mu sync.Mutex
	m := map[string]*visitor{}
	return func(c *gin.Context) {
		ip, now := c.ClientIP(), time.Now()
		mu.Lock()
		if len(m) > limiterSweepLen {
			for k, v := range m {
				if now.Sub(v.seen) > limiterIdleTTL {
					delete(m, k)
				}
			}
		}
		v, ok := m[ip]
		if !ok {
			v = &visitor{lim: rate.NewLimiter(r, b)}
			m[ip] = v
		}
		v.seen = now
		allowed := v.lim.Allow()
		mu.Unlock()
		if !allowed {
			fail(c, "Please wait 1 seconds between each post.")
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
