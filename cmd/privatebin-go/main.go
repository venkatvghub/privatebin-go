package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/venkatvghub/privatebin-go/internal/auth"
	"github.com/venkatvghub/privatebin-go/internal/config"
	"github.com/venkatvghub/privatebin-go/internal/httpapi"
	"github.com/venkatvghub/privatebin-go/internal/obs"
	"github.com/venkatvghub/privatebin-go/internal/paste"
	"github.com/venkatvghub/privatebin-go/internal/purge"
	"github.com/venkatvghub/privatebin-go/web"
	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		os.Exit(1)
	}
	log, err := obs.NewLogger(cfg.AppName, cfg.LogLevel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "logger:", err)
		os.Exit(1)
	}
	defer log.Sync()
	gin.SetMode(gin.ReleaseMode)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	db, err := gorm.Open(postgres.Open(cfg.DatabaseURL), &gorm.Config{Logger: logger.New(stdlog.New(os.Stderr, "", stdlog.LstdFlags), logger.Config{LogLevel: logger.Warn, IgnoreRecordNotFoundError: true}), NamingStrategy: paste.NamingStrategy(cfg.TablePrefix)})
	if err != nil {
		log.Fatal("db open", zap.Error(err))
	}
	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(20)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	m := obs.NewMetrics()
	svc := paste.New(db, cfg.DeleteSalt)
	if err := svc.Migrate(cfg.TablePrefix); err != nil {
		log.Fatal("migrate", zap.Error(err))
	}
	go purge.Run(ctx, log, svc, time.Minute)

	var a *auth.Auth
	if cfg.AuthEnabled {
		if a, err = auth.New(ctx, cfg); err != nil {
			log.Fatal("auth init", zap.Error(err))
		}
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           httpapi.NewRouter(httpapi.Deps{Log: log, Metrics: m, Cfg: cfg, Paste: svc, DB: db, Auth: a, Static: web.FS()}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if cfg.MetricsAddr != "" {
		go serve(ctx, log, &http.Server{Addr: cfg.MetricsAddr, Handler: m.Handler(), ReadHeaderTimeout: 10 * time.Second})
	}
	log.Info("listening", zap.String("addr", cfg.ListenAddr), zap.Bool("auth", cfg.AuthEnabled), zap.String("metrics", cfg.MetricsAddr))
	serve(ctx, log, srv)
}

// serve runs srv until ctx is cancelled, then shuts it down gracefully.
func serve(ctx context.Context, log *zap.Logger, srv *http.Server) {
	go func() {
		<-ctx.Done()
		// ctx is already cancelled here, so shutdown needs its own deadline.
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second) // #nosec G118
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		log.Error("serve", zap.String("addr", srv.Addr), zap.Error(err))
	}
}
