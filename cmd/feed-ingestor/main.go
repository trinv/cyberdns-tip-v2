// Command feed-ingestor thu thập các nguồn blocklist/CTI, chuẩn hóa rồi nạp vào tầng
// bằng chứng L0 và mô hình canonical L1 trong PostgreSQL.
//
// Một nguồn hỏng chỉ làm hỏng lần import của chính nó: dữ liệu cũ giữ nguyên, snapshot
// đang phát hành không đổi, và chu kỳ vẫn chạy tiếp sang nguồn khác.
//
// Ngoài chu kỳ định kỳ, service còn lắng nghe yêu cầu "đồng bộ ngay" từ dashboard qua
// bảng admin_triggers (kind='sync') — xem internal/app.RunLoopWithTrigger.
package main

import (
	"context"
	"fmt"
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

	db := store.New(svc.Pool)
	ing := &ingest.Ingestor{
		DB:      db,
		Fetcher: feed.NewFetcher(),
		Metrics: svc.Metrics,
		Log:     svc.Log,
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	job := func(ctx context.Context, now time.Time, sourceID *int64) (any, error) {
		// sourceID != nil: dashboard yêu cầu đồng bộ đúng MỘT nguồn, không phải cả chu
		// kỳ. Đường này bỏ qua cờ "enabled" một cách có chủ ý — thử một nguồn trước khi
		// bật nó là cách hợp lý để kiểm tra URL/định dạng mà không cần chỉnh CSDL.
		if sourceID != nil {
			src, err := db.SourceByID(ctx, *sourceID)
			if err != nil {
				return nil, err
			}
			if src.Origin != "direct" {
				return nil, fmt.Errorf(
					"nguồn %q có origin=%q: feed-ingestor chỉ đồng bộ nguồn 'direct', "+
						"nguồn 'opencti' đồng bộ qua sync-consumer", src.Name, src.Origin)
			}
			svc.Metrics.InitSource(src.Name)
			return ing.One(ctx, src, now)
		}

		results, err := ing.All(ctx, now)
		if err != nil {
			return results, err
		}
		svc.Log.Info("chu kỳ thu thập xong", "sources", len(results))
		return results, nil
	}

	go svc.RunLoopWithTrigger(runCtx, "ingest", store.TriggerSync, db,
		svc.Cfg.Schedule.Interval, svc.Cfg.Schedule.TriggerPoll, svc.Cfg.Schedule.RunAtStart, job)

	if err := svc.RunServers(ctx, svc.Ready(), nil); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
	stop()
}
