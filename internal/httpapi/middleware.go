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

// newLimiter is a per-IP token bucket (r tokens/sec, burst b).
func newLimiter(r rate.Limit, b int) gin.HandlerFunc {
	var mu sync.Mutex
	m := map[string]*rate.Limiter{}
	return func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		l, ok := m[ip]
		if !ok {
			if len(m) > 10000 {
				m = map[string]*rate.Limiter{}
			}
			l = rate.NewLimiter(r, b)
			m[ip] = l
		}
		mu.Unlock()
		if !l.Allow() {
			fail(c, "Please wait 1 seconds between each post.")
			return
		}
		c.Next()
	}
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
