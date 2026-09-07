// Command blocklist-generator dựng bộ snapshot blocklist từ quyết định trong
// PostgreSQL, phát hành theo bộ, và phục vụ chúng qua HTTP tại tip.cyberdns.vn.
//
// Việc dựng và việc phục vụ tách rời nhau: phần phục vụ chỉ đọc thư mục snapshot, nên
// sự cố PostgreSQL không làm gián đoạn các URL — bộ đã publish gần nhất vẫn được trả về.
package main

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/blocklistsrv"
	"github.com/vnnic/cyberdns-tip/internal/builder"
	"github.com/vnnic/cyberdns-tip/internal/render"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "blocklist-generator")
	if err != nil {
		log.Fatalf("khởi động blocklist-generator: %v", err)
	}
	defer svc.Close()

	snaps, err := snapshot.NewStore(svc.Cfg.Snapshot.Root, svc.Cfg.Snapshot.Keep)
	if err != nil {
		svc.Log.Error("mở kho snapshot", "err", err)
		return
	}

	build := &builder.Builder{
		DB:      store.New(svc.Pool),
		Store:   snaps,
		Metrics: svc.Metrics,
		Log:     svc.Log,
		Format:  render.FormatDomain,
	}

	public := blocklistsrv.New(blocklistsrv.Options{
		Store:       snaps,
		Metrics:     svc.Metrics,
		Log:         svc.Log,
		CacheMaxAge: svc.Cfg.Public.CacheMaxAge,
	})

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	go svc.RunLoop(runCtx, "build",
		svc.Cfg.Schedule.Interval, svc.Cfg.Schedule.RunAtStart,
		func(ctx context.Context, now time.Time) error {
			_, err := build.Build(ctx, now)
			// Chưa có lượt policy nào là trạng thái khởi đầu bình thường, không phải
			// lỗi: hệ vừa dựng xong và chưa nạp nguồn nào.
			if errors.Is(err, builder.ErrNoPolicyRun) {
				svc.Log.Info("chưa có lượt policy nào, chưa dựng snapshot")
				return nil
			}
			return err
		})

	go trackSnapshotAge(runCtx, svc, snaps)

	// Readiness gắn với kho snapshot chứ không gắn với PostgreSQL: service này phục vụ
	// được bằng bộ đã publish ngay cả khi control plane đang hỏng, nên báo chưa sẵn
	// sàng vì PostgreSQL không trả lời là sai.
	ready := func(context.Context) error {
		_, err := snaps.Current()
		return err
	}

	if err := svc.RunServers(ctx, ready, public.Handler()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
	stop()
}

// trackSnapshotAge cập nhật metric tuổi snapshot để cảnh báo SnapshotStale hoạt động.
//
// Phải là một vòng lặp riêng chứ không tính lúc dựng: nếu chỉ cập nhật khi dựng thành
// công thì đúng lúc việc dựng ngừng hoạt động, metric sẽ đứng yên và cảnh báo im lặng.
func trackSnapshotAge(ctx context.Context, svc *app.Service, snaps *snapshot.Store) {
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			m, err := snaps.Manifest()
			if err != nil {
				continue
			}
			built, err := time.Parse(time.RFC3339, m.GeneratedAt)
			if err != nil {
				continue
			}
			svc.Metrics.SnapshotAgeSec.WithLabelValues("public").
				Set(time.Since(built).Seconds())
		}
	}
}
