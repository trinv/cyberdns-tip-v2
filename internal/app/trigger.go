package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/store"
)

// TriggerJob chạy một lượt việc.
//
// sourceID khác nil khi đây là yêu cầu thủ công nhắm vào một nguồn cụ thể — chỉ
// feed-ingestor (kind "sync") dùng tới nó; policy-engine và blocklist-generator luôn
// nhận nil vì chúng không có khái niệm "một nguồn".
//
// summary được mã hóa JSON và lưu vào yêu cầu để dashboard hiển thị kết quả sau khi
// xong; trả về nil nếu không có gì đáng lưu.
type TriggerJob func(ctx context.Context, now time.Time, sourceID *int64) (summary any, err error)

// triggerStore là phần của store.Store mà vòng lặp trigger cần.
type triggerStore interface {
	ClaimTrigger(ctx context.Context, kind string) (store.Trigger, bool, error)
	FinishTrigger(ctx context.Context, id int64, status, result, errMsg string) error
}

// RunLoopWithTrigger chạy job theo chu kỳ CỘNG với xen kẽ tiêu thụ yêu cầu "chạy ngay"
// từ dashboard (bảng admin_triggers) — nhưng cả hai đường kích hoạt đi qua CÙNG MỘT
// goroutine, nên không bao giờ có hai lượt job chạy chồng lên nhau, dù kích hoạt từ
// đâu.
//
// Đây là điều kiện bắt buộc chứ không phải tiện lợi: nếu tách hai đường kích hoạt ra
// hai goroutine riêng, một yêu cầu "đồng bộ ngay" từ dashboard có thể rơi đúng lúc lượt
// theo chu kỳ đang xử lý CÙNG một nguồn — hai lần Apply() chồng lên nhau cho cùng
// source_id, mỗi bên tưởng mình là lần chạy gần nhất, và bảng feed_imports ghi lại hai
// bản ghi mâu thuẫn nhau về "trạng thái hiện tại của nguồn này".
//
// Mỗi lượt của ticker (pollInterval) làm quyết định: có yêu cầu thủ công đang chờ thì
// xử lý nó ngay, không thì mới xét đã tới hạn lượt theo chu kỳ chưa. Nghĩa là yêu cầu
// thủ công luôn được ưu tiên hơn lượt theo lịch, và một loạt yêu cầu xếp hàng được rút
// dần mỗi pollInterval một cái.
func (s *Service) RunLoopWithTrigger(
	ctx context.Context,
	name, kind string,
	db triggerStore,
	interval, pollInterval time.Duration,
	runAtStart bool,
	job TriggerJob,
) {
	if pollInterval <= 0 {
		pollInterval = 3 * time.Second
	}

	nextScheduled := time.Now()
	if !runAtStart {
		nextScheduled = nextScheduled.Add(interval)
	}

	timer := time.NewTimer(pollInterval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			s.Log.Info("dừng vòng lặp", "job", name)
			return
		case <-timer.C:
			timer.Reset(pollInterval)

			if s.consumeTrigger(ctx, name, kind, db, job) {
				// Còn khả năng có yêu cầu khác đang xếp hàng; xử lý nốt trước khi xét
				// tới lịch, để nhiều yêu cầu liên tiếp không phải chờ xen giữa các lượt
				// theo chu kỳ.
				continue
			}

			now := time.Now()
			if now.Before(nextScheduled) {
				continue
			}
			s.runScheduled(ctx, name, job)
			nextScheduled = now.Add(interval)
		}
	}
}

// consumeTrigger nhận và chạy MỘT yêu cầu thủ công, nếu có. Trả về true khi có yêu cầu
// để xử lý — dù kết quả thành công hay thất bại.
func (s *Service) consumeTrigger(ctx context.Context, name, kind string, db triggerStore, job TriggerJob) bool {
	t, ok, err := db.ClaimTrigger(ctx, kind)
	if err != nil {
		s.Log.Error("đọc yêu cầu thủ công", "job", name, "err", err)
		return false
	}
	if !ok {
		return false
	}

	start := time.Now()
	summary, jerr := job(ctx, start, t.SourceID)
	dur := time.Since(start).Round(time.Millisecond)

	if jerr != nil {
		s.Log.Error("yêu cầu thủ công thất bại",
			"job", name, "trigger", t.ID, "err", jerr, "duration", dur)
		if err := db.FinishTrigger(ctx, t.ID, "failed", "", jerr.Error()); err != nil {
			s.Log.Error("đóng yêu cầu thất bại", "trigger", t.ID, "err", err)
		}
		s.countTrigger(kind, "failed")
		return true
	}

	raw, err := json.Marshal(summary)
	if err != nil {
		// Không lưu được kết quả không phải lý do để coi cả yêu cầu là thất bại: việc
		// nó yêu cầu đã CHẠY XONG thật sự, chỉ là dashboard sẽ không thấy chi tiết.
		s.Log.Error("mã hóa kết quả yêu cầu", "trigger", t.ID, "err", err)
		raw = nil
	}

	s.Log.Info("yêu cầu thủ công xong", "job", name, "trigger", t.ID, "duration", dur)
	if err := db.FinishTrigger(ctx, t.ID, "done", string(raw), ""); err != nil {
		s.Log.Error("đóng yêu cầu", "trigger", t.ID, "err", err)
	}
	s.countTrigger(kind, "done")
	return true
}

// runScheduled chạy một lượt theo lịch — không gắn với yêu cầu thủ công nào.
func (s *Service) runScheduled(ctx context.Context, name string, job TriggerJob) {
	start := time.Now()
	_, err := job(ctx, start, nil)
	if err != nil {
		if ctx.Err() != nil {
			return // đang tắt, không phải lỗi
		}
		s.Log.Error("lượt chạy thất bại", "job", name, "err", err,
			"duration", time.Since(start).Round(time.Millisecond))
		return
	}
	s.Log.Debug("lượt chạy xong", "job", name,
		"duration", time.Since(start).Round(time.Millisecond))
}

func (s *Service) countTrigger(kind, outcome string) {
	if s.Metrics == nil || s.Metrics.AdminTriggers == nil {
		return
	}
	s.Metrics.AdminTriggers.WithLabelValues(kind, outcome).Inc()
}
