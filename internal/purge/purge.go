package purge

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/venkatvghub/privatebin-go/internal/paste"
)

func Run(ctx context.Context, log *zap.Logger, s *paste.Service, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n, err := s.PurgeExpired(); err != nil {
				log.Error("purge failed", zap.Error(err))
			} else if n > 0 {
				log.Info("purged expired pastes", zap.Int64("count", n))
			}
		}
	}
}
