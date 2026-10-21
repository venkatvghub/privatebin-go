package obs

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// NewLogger returns a JSON zap logger; every line carries app=<appName>.
func NewLogger(appName, level string) (*zap.Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		return nil, err
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.EncoderConfig.TimeKey = "ts"
	cfg.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	cfg.InitialFields = map[string]any{"app": appName}
	return cfg.Build()
}
