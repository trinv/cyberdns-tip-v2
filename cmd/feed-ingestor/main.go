// Command feed-ingestor thu thập các nguồn blocklist/CTI, chuẩn hóa rồi nạp vào tầng
// bằng chứng L0 và mô hình canonical L1 trong PostgreSQL.
//
// Một nguồn hỏng chỉ làm hỏng lần import của chính nó: dữ liệu cũ giữ nguyên, snapshot
// đang phát hành không đổi, và chu kỳ vẫn chạy tiếp sang nguồn khác.
package main

import (
	"context"
	"log"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/feed"
	"github.com/vnnic/cyberdns-tip/internal/ingest"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "feed-ingestor")
	if err != nil {
		log.Fatalf("khởi động feed-ingestor: %v", err)
	}
	defer svc.Close()

	ing := &ingest.Ingestor{
		DB:      store.New(svc.Pool),
		Fetcher: feed.NewFetcher(),
		Metrics: svc.Metrics,
		Log:     svc.Log,
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	go svc.RunLoop(runCtx, "ingest",
		svc.Cfg.Schedule.Interval, svc.Cfg.Schedule.RunAtStart,
		func(ctx context.Context, now time.Time) error {
			results, err := ing.All(ctx, now)
			if err != nil {
				return err
			}
			svc.Log.Info("chu kỳ thu thập xong", "sources", len(results))
			return nil
		})

	if err := svc.RunServers(ctx, svc.Ready(), nil); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
	stop()
}
