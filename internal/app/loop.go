package app

import (
	"context"
	"time"
)

// Job là một lượt công việc. Trả lỗi thì lượt đó coi như hỏng, nhưng vòng lặp vẫn chạy
// tiếp: một chu kỳ hỏng không được làm chết service.
type Job func(ctx context.Context, now time.Time) error

// RunLoop chạy job theo chu kỳ cho tới khi ctx bị hủy.
//
// Chu kỳ tính từ lúc lượt trước KẾT THÚC, không phải từ lúc bắt đầu. Với ticker cố
// định, một lượt chạy lâu hơn chu kỳ sẽ khiến các lượt sau dồn đống và chạy liên tục —
// đúng lúc hệ đang chậm thì lại chất thêm tải.
func (s *Service) RunLoop(ctx context.Context, name string, interval time.Duration, runAtStart bool, job Job) {
	if runAtStart {
		s.runOnce(ctx, name, job)
	}

	timer := time.NewTimer(interval)
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			s.Log.Info("dừng vòng lặp", "job", name)
			return
		case <-timer.C:
			s.runOnce(ctx, name, job)
			timer.Reset(interval)
		}
	}
}

func (s *Service) runOnce(ctx context.Context, name string, job Job) {
	start := time.Now()
	if err := job(ctx, start); err != nil {
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
