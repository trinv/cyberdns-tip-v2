package syncconsumer

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/opencti"
)

// LastEventID là id sự kiện gần nhất đã xử lý, dùng để nối lại đúng chỗ.
func (c *Consumer) LastEventID() string { return c.pendingID }

// RunOptions là cấu hình vòng lặp kết nối lại.
type RunOptions struct {
	Stream opencti.StreamConfig

	MinBackoff time.Duration
	MaxBackoff time.Duration
}

// Run giữ kết nối Live Stream cho tới khi ctx bị hủy.
//
// Kết nối SSE nào cũng đứt: OpenCTI khởi động lại, reverse proxy hết hạn chờ, mạng chớp.
// Đó là chuyện bình thường chứ không phải sự cố, nên vòng lặp này im lặng nối lại thay
// vì để service thoát và trông cậy vào việc container được khởi động lại.
//
// Mỗi lần nối lại đều bắt đầu từ id sự kiện cuối đã xử lý. Bỏ qua việc đó thì mỗi lần
// đứt kết nối là một khoảng dữ liệu mất hẳn — và với luồng CTI thì mất chính là những
// thay đổi mới nhất, thứ đáng giá nhất.
func (c *Consumer) Run(ctx context.Context, opts RunOptions) error {
	if opts.MinBackoff <= 0 {
		opts.MinBackoff = time.Second
	}
	if opts.MaxBackoff <= 0 {
		opts.MaxBackoff = 2 * time.Minute
	}

	backoff := opts.MinBackoff
	cfg := opts.Stream

	for {
		if err := ctx.Err(); err != nil {
			return c.Flush(context.WithoutCancel(ctx))
		}

		start := c.opts.Now()
		err := opencti.Listen(ctx, cfg, c.Handle)

		// Ghi checkpoint ngay khi kết nối đóng, dù đóng vì lý do gì. Bỏ qua bước này thì
		// mọi sự kiện chưa đủ lô sẽ bị xử lý lại sau khi nối lại.
		if ferr := c.Flush(context.WithoutCancel(ctx)); ferr != nil {
			c.opts.Log.Error("ghi checkpoint thất bại", "err", ferr)
		}

		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil
		}

		// Nối lại từ chỗ đã dừng. Sau lần này thì không dùng recover nữa: nó chỉ để bù
		// khoảng ngừng dài lúc khởi động, còn ở đây đã có id sự kiện chính xác.
		if id := c.LastEventID(); id != "" {
			cfg.StartFrom = id
			cfg.Recover = nil
		}

		// Kết nối sống được lâu thì coi như lành và đặt lại backoff. Không có bước này,
		// một service chạy nhiều tháng sẽ dần dần chờ tới hai phút cho mỗi lần nối lại
		// dù mỗi lần đứt cách nhau hàng tuần.
		if c.opts.Now().Sub(start) > time.Minute {
			backoff = opts.MinBackoff
		}

		level := c.opts.Log.Warn
		if err == nil || errors.Is(err, context.Canceled) {
			level = c.opts.Log.Info
		}
		level("mất kết nối Live Stream, sẽ nối lại",
			"err", err, "backoff", backoff.Round(time.Millisecond), "start_from", cfg.StartFrom)

		if !sleep(ctx, jitter(backoff)) {
			return nil
		}

		backoff *= 2
		if backoff > opts.MaxBackoff {
			backoff = opts.MaxBackoff
		}
	}
}

// jitter làm lệch ngẫu nhiên khoảng chờ trong phạm vi ±25%.
//
// Nếu OpenCTI khởi động lại, mọi consumer đều mất kết nối cùng lúc và sẽ nối lại cùng
// lúc, dồn một đợt tải đúng vào lúc nó vừa mới dậy.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	delta := float64(d) * 0.25
	return time.Duration(float64(d) - delta + rand.Float64()*2*delta)
}

// sleep chờ d hoặc tới khi ctx bị hủy. Trả false nếu ctx hủy trước.
func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
