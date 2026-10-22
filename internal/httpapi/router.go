package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/venkatvghub/privatebin-go/internal/auth"
	"github.com/venkatvghub/privatebin-go/internal/config"
	"github.com/venkatvghub/privatebin-go/internal/obs"
	"github.com/venkatvghub/privatebin-go/internal/paste"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type Deps struct {
	Log     *zap.Logger
	Metrics *obs.Metrics
	Cfg     *config.Config
	Paste   *paste.Service
	DB      *gorm.DB
	Auth    *auth.Auth // nil when AUTH_ENABLED=false
	Static  fs.FS
}

// idRe matches ids from paste.newID; web/js/app.js mirrors it.
var idRe = regexp.MustCompile(`^[a-f0-9]{16}$`)

// Messages copied from PrivateBin so clients matching on them keep working.
const (
	msgNotFound   = "Paste does not exist, has expired or has been deleted."
	msgInvalid    = "Invalid data."
	msgWrongToken = "Wrong deletion token. Paste was not deleted." // #nosec G101 -- PrivateBin message text, not a credential
)

func NewRouter(d Deps) *gin.Engine {
	r := gin.New()
	if err := r.SetTrustedProxies(d.Cfg.TrustedProxies); err != nil {
		panic(err) // misconfigured TRUSTED_PROXIES; fail at startup
	}
	r.Use(recoverer(d.Log), observe(d.Log, d.Metrics), securityHeaders())

	r.GET("/healthz", func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), time.Second)
		defer cancel()
		sqlDB, err := d.DB.DB()
		if err != nil || sqlDB.PingContext(ctx) != nil {
			c.Status(http.StatusServiceUnavailable)
			return
		}
		c.String(http.StatusOK, "ok")
	})

	create := []gin.HandlerFunc{newLimiter(1, 10), bodyLimit(d.Cfg.MaxPasteBytes)}
	if d.Auth != nil {
		d.Auth.Routes(r)
		create = append([]gin.HandlerFunc{d.Auth.Require()}, create...)
	}

	// PrivateBin-compatible JSON API: everything lives on "/".
	index := d.asset("index.html")
	r.GET("/", func(c *gin.Context) {
		if isJSON(c) {
			d.jsonGet(c)
			return
		}
		index(c)
	})
	r.POST("/", append(create, func(c *gin.Context) {
		if !isJSON(c) {
			fail(c, msgInvalid)
			return
		}
		d.jsonPost(c)
	})...)

	// privatebin-go extensions (not part of PrivateBin's API).
	r.GET("/api/config", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"authEnabled": d.Auth != nil,
			"loggedIn":    d.Auth != nil && d.Auth.LoggedIn(c),
			"maxBytes":    d.Cfg.MaxPasteBytes,
		})
	})
	r.GET("/api/paste/:id/meta", func(c *gin.Context) {
		id := c.Param("id")
		if !idRe.MatchString(id) {
			fail(c, msgInvalid)
			return
		}
		burn, err := d.Paste.IsBurn(id)
		if err != nil {
			d.readError(c, err)
			return
		}
		c.JSON(200, gin.H{"status": 0, "burn": burn})
	})

	if d.Cfg.SwaggerEnabled {
		r.GET("/openapi.yaml", d.asset("openapi.yaml"))
		docs := r.Group("/swagger", swaggerCSP())
		docs.GET("", func(c *gin.Context) { c.Redirect(http.StatusMovedPermanently, "/swagger/") })
		docs.GET("/", d.asset("swagger/index.html"))
		docs.GET("/init.js", d.asset("swagger/init.js"))
	}

	files := http.FileServer(http.FS(d.Static))
	r.NoRoute(func(c *gin.Context) {
		if c.Request.Method != http.MethodGet && c.Request.Method != http.MethodHead {
			c.Status(http.StatusNotFound)
			return
		}
		if _, err := fs.Stat(d.Static, strings.TrimPrefix(path.Clean(c.Request.URL.Path), "/")); err == nil {
			setStaticCache(c)
		}
		files.ServeHTTP(c.Writer, c.Request)
	})
	return r
}

// asset serves one embedded file. Files are read per request from the embedded
// FS (cheap) so no redirect logic of http.ServeFile applies to index.html.
func (d Deps) asset(name string) gin.HandlerFunc {
	return func(c *gin.Context) {
		b, err := fs.ReadFile(d.Static, name)
		if err != nil {
			c.Status(http.StatusNotFound)
			return
		}
		c.Data(http.StatusOK, mime.TypeByExtension(path.Ext(name)), b)
	}
}

// isJSON mirrors PrivateBin: JSON API mode is selected by this header.
func isJSON(c *gin.Context) bool {
	return strings.EqualFold(c.GetHeader("X-Requested-With"), "JSONHttpRequest")
}

// pasteID extracts the id from "?<id>" or "?pasteid=<id>".
func pasteID(c *gin.Context) string {
	if v := c.Query("pasteid"); v != "" {
		return v
	}
	for k, vs := range c.Request.URL.Query() {
		if len(vs) == 1 && vs[0] == "" && idRe.MatchString(k) {
			return k
		}
	}
	return ""
}

func (d Deps) jsonGet(c *gin.Context) {
	id := pasteID(c)
	if !idRe.MatchString(id) {
		fail(c, msgInvalid)
		return
	}
	if tok := c.Query("deletetoken"); tok != "" {
		d.jsonDelete(c, id, tok)
		return
	}
	v, err := d.Paste.Read(id)
	if err != nil {
		d.readError(c, err)
		return
	}
	if v.Burned {
		d.Metrics.PastesBurned.Inc()
	}
	meta := gin.H{"created": v.Created}
	if v.TimeToLive != nil {
		meta["time_to_live"] = *v.TimeToLive
	}
	c.Header("Cache-Control", "no-store")
	c.JSON(200, gin.H{
		"status": 0, "id": id, "url": "?" + id, "v": v.Stored.V, "adata": v.Stored.AData, "ct": v.Stored.CT,
		"meta": meta, "comments": []any{}, "comment_count": 0, "comment_offset": 0,
		"@context": "?jsonld=paste",
	})
}

func (d Deps) jsonDelete(c *gin.Context, id, tok string) {
	switch err := d.Paste.Delete(id, tok); {
	case errors.Is(err, paste.ErrWrongToken):
		fail(c, msgWrongToken)
	case err != nil:
		d.readError(c, err)
	default:
		c.JSON(200, gin.H{"status": 0, "id": id, "url": "?" + id})
	}
}

func (d Deps) jsonPost(c *gin.Context) {
	var in paste.Input
	if err := c.ShouldBindJSON(&in); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			fail(c, fmt.Sprintf("Paste is limited to %s of encrypted data.", humanSize(d.Cfg.MaxPasteBytes)))
			return
		}
		fail(c, msgInvalid)
		return
	}
	if in.PasteID != "" {
		fail(c, "Discussions are disabled.")
		return
	}
	id, tok, burn, err := d.Paste.Create(&in)
	switch {
	case errors.Is(err, paste.ErrInvalid):
		fail(c, msgInvalid)
	case err != nil:
		d.serverError(c, "create paste", err)
	default:
		d.Metrics.PastesCreated.WithLabelValues(strconv.FormatBool(burn)).Inc()
		c.Header("Cache-Control", "no-store") // response carries the delete token
		c.JSON(200, gin.H{"status": 0, "id": id, "url": "?" + id, "deletetoken": tok})
	}
}

// readError maps service errors to PrivateBin responses.
func (d Deps) readError(c *gin.Context, err error) {
	if errors.Is(err, paste.ErrNotFound) {
		fail(c, msgNotFound)
		return
	}
	d.serverError(c, "paste request", err)
}

// fail mirrors PrivateBin: errors are HTTP 200 with status=1.
func fail(c *gin.Context, msg string) {
	c.AbortWithStatusJSON(http.StatusOK, gin.H{"status": 1, "message": msg})
}

func (d Deps) serverError(c *gin.Context, what string, err error) {
	d.Log.Error(what, zap.Error(err))
	fail(c, "Internal error.")
}

func humanSize(n int64) string {
	if n >= 1<<20 {
		return fmt.Sprintf("%.2f MiB", float64(n)/(1<<20))
	}
	return fmt.Sprintf("%.2f KiB", float64(n)/(1<<10))
}
