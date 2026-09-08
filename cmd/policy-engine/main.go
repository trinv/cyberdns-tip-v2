// Command policy-engine chuyển bằng chứng ở L1 thành quyết định BLOCK/MONITOR/ALLOW
// theo từng cặp (domain, category), rồi ghi xuống L2.
//
// Mỗi lượt chạy được đánh dấu bằng một policy_run_id; blocklist-generator chỉ dựng
// snapshot từ lượt đã hoàn tất nên không bao giờ đọc phải trạng thái nửa cũ nửa mới.
//
// Ngoài chu kỳ định kỳ, service còn lắng nghe yêu cầu "chấm điểm lại ngay" từ dashboard
// qua bảng admin_triggers (kind='policy') — xem internal/app.RunLoopWithTrigger.
package main

import (
	"context"
	"log"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/policy"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "policy-engine")
	if err != nil {
		log.Fatalf("khởi động policy-engine: %v", err)
	}
	defer svc.Close()

	db := store.New(svc.Pool)

	// TODO(P5): nạp cấu hình policy từ CSDL để đổi ngưỡng không cần deploy lại.
	cfg := policy.DefaultConfig()
	if err := cfg.Validate(); err != nil {
		svc.Log.Error("cấu hình policy không hợp lệ", "err", err)
		return
	}

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	job := func(ctx context.Context, now time.Time, _ *int64) (any, error) {
		return runOnce(ctx, svc, db, cfg, now)
	}

	go svc.RunLoopWithTrigger(runCtx, "policy", store.TriggerPolicy, db,
		svc.Cfg.Schedule.Interval, svc.Cfg.Schedule.TriggerPoll, svc.Cfg.Schedule.RunAtStart, job)

	if err := svc.RunServers(ctx, svc.Ready(), nil); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
	stop()
}

func runOnce(ctx context.Context, svc *app.Service, db *store.Store, cfg policy.Config, now time.Time) (store.RunStats, error) {
	runID, err := db.BeginPolicyRun(ctx, cfg, false)
	if err != nil {
		return store.RunStats{}, err
	}

	lists, err := db.LoadLists(ctx, now)
	if err != nil {
		_ = db.FinishPolicyRun(ctx, runID, "failed", 0, 0, err.Error())
		return store.RunStats{}, err
	}

	start := time.Now()
	stats, err := db.EvaluateAll(ctx, runID, cfg, lists, now)
	if err != nil {
		// Đánh dấu hỏng chứ không bỏ mặc: lượt mắc kẹt ở 'running' sẽ không bao giờ
		// được generator dùng, mà cũng không ai biết vì sao.
		_ = db.FinishPolicyRun(ctx, runID, "failed", stats.Evaluated, stats.Blocked, err.Error())
		return stats, err
	}

	if err := db.FinishPolicyRun(ctx, runID, "completed", stats.Evaluated, stats.Blocked, ""); err != nil {
		return stats, err
	}

	svc.Metrics.PolicyRunDurationSec.Observe(time.Since(start).Seconds())
	svc.Log.Info("lượt policy xong",
		"run", runID, "evaluated", stats.Evaluated, "blocked", stats.Blocked,
		"changed", stats.Changed, "duration", time.Since(start).Round(time.Millisecond))
	return stats, nil
}
