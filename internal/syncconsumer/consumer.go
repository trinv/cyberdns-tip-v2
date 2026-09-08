// Package syncconsumer nối OpenCTI Live Stream vào L1.
//
// Đây là tầng điều phối: nó không phân tích STIX (việc của package opencti) và không
// viết SQL (việc của package store). Nó quyết định mỗi loại sự kiện dẫn tới thao tác ghi
// nào, và đó là nơi các xung đột B3, B5, B6 được xử lý.
package syncconsumer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/opencti"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// Kết cục của một sự kiện, dùng làm nhãn metric.
const (
	outcomeApplied = "applied"
	outcomeSkipped = "skipped"
	outcomeStale   = "stale"
	outcomeFailed  = "failed"
)

// Store là phần của store mà consumer dùng. Thu hẹp thành interface để test được logic
// điều phối mà không cần PostgreSQL.
type Store interface {
	UpsertOpenCTI(ctx context.Context, src store.Source, rec store.OpenCTIRecord, now time.Time) error
	DeleteOpenCTI(ctx context.Context, sourceID int64, stixID string) (int64, error)
	MergeOpenCTI(ctx context.Context, sourceID int64, from []string, to string) (int64, error)
	SaveStreamState(ctx context.Context, sourceID int64, streamID, eventID string, eventAt time.Time, processed int64) error
}

// Options là cấu hình của một consumer.
type Options struct {
	Source   store.Source
	StreamID string

	// LabelCategories ánh xạ nhãn OpenCTI sang category. Nhãn không có trong bảng này
	// bị bỏ qua; indicator không khớp nhãn nào dùng category mặc định của nguồn.
	LabelCategories map[string][]int16

	// CheckpointEvery và CheckpointAfter quyết định nhịp ghi checkpoint.
	//
	// Ghi mỗi sự kiện một lần là một transaction cho mỗi indicator chỉ để lưu một chuỗi
	// id — ở nhịp nhập hàng loạt của OpenCTI thì đó là phần lớn tải ghi. Ghi thưa thì
	// tệ nhất là xử lý lại vài sự kiện sau khi khởi động lại, mà đường ghi đã idempotent.
	CheckpointEvery int
	CheckpointAfter time.Duration

	Log     *slog.Logger
	Metrics *metrics.Metrics

	// Now cho phép test cố định đồng hồ.
	Now func() time.Time
}

// Consumer áp dụng sự kiện Live Stream vào CSDL.
type Consumer struct {
	db   Store
	opts Options

	// Trạng thái checkpoint chờ ghi.
	pendingID    string
	pendingAt    time.Time
	pendingCount int64
	lastFlush    time.Time
}

// New dựng consumer.
func New(db Store, opts Options) *Consumer {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.CheckpointEvery <= 0 {
		opts.CheckpointEvery = 100
	}
	if opts.CheckpointAfter <= 0 {
		opts.CheckpointAfter = 10 * time.Second
	}
	return &Consumer{db: db, opts: opts, lastFlush: opts.Now()}
}

// Handle áp dụng một sự kiện.
//
// Chỉ trả lỗi khi tình huống KHÔNG thể tiếp tục được (mất CSDL). Sự kiện không hiểu
// được, không nói về tên miền, hoặc đã cũ đều là đường đi bình thường của một luồng
// CTI thật: chúng được đếm rồi bỏ qua. Dừng cả stream vì một indicator hash file sẽ
// biến consumer thành thứ không bao giờ chạy quá vài giây.
func (c *Consumer) Handle(ctx context.Context, ev opencti.Event) error {
	now := c.opts.Now()
	kind := ev.Normalized()

	var err error
	switch kind {
	case opencti.EventDelete:
		err = c.handleDelete(ctx, ev)
	case opencti.EventMerge:
		err = c.handleMerge(ctx, ev, now)
	default:
		err = c.handleUpsert(ctx, ev, now)
	}

	c.pendingID = ev.ID
	c.pendingCount++
	if t := eventTime(ev); !t.IsZero() {
		c.pendingAt = t
		// Độ trễ đo từ đồng hồ của OpenCTI tới lúc áp dụng xong. Đây là chỉ số vận hành:
		// OpenCTI nằm trong đường sinh blocklist, nên trễ ở đây là trễ tới khi một
		// domain thực sự bị chặn.
		if c.opts.Metrics != nil {
			c.opts.Metrics.StreamLagSec.Set(now.Sub(t).Seconds())
		}
	}

	if err != nil {
		return err
	}
	return c.maybeFlush(ctx, now)
}

func (c *Consumer) handleUpsert(ctx context.Context, ev opencti.Event, now time.Time) error {
	rec, err := opencti.FromSTIX(ev.Object)
	if err != nil {
		// Luồng CTI thật chở đủ thứ: IP, hash file, malware, campaign, quan hệ. Phần
		// lớn không nói về tên miền và đó không phải lỗi.
		c.count(ev.Type, outcomeSkipped)
		return nil
	}

	// detection=false nghĩa là indicator chỉ để phân tích. Chặn theo nó là làm trái ý
	// analyst đã ghi rõ.
	if !rec.Detection {
		c.count(ev.Type, outcomeSkipped)
		return nil
	}

	categories := c.categoriesFor(rec.Labels)

	err = c.db.UpsertOpenCTI(ctx, c.opts.Source, store.OpenCTIRecord{
		STIXID:      rec.STIXID,
		Rules:       rec.Rules,
		CategoryIDs: categories,
		Confidence:  rec.Confidence,
		Revoked:     rec.Revoked,
		ValidUntil:  rec.ValidUntil,
		Modified:    rec.Modified,
		RawLine:     rawLine(ev.Object),
	}, now)

	switch {
	case errors.Is(err, store.ErrStale):
		// Phát lại sau khi kết nối lại. Đường đi bình thường, không phải lỗi.
		c.count(ev.Type, outcomeStale)
		return nil
	case err != nil:
		c.count(ev.Type, outcomeFailed)
		return fmt.Errorf("syncconsumer: ghi %s: %w", rec.STIXID, err)
	}

	c.count(ev.Type, outcomeApplied)
	return nil
}

func (c *Consumer) handleDelete(ctx context.Context, ev opencti.Event) error {
	id := objectID(ev.Object)
	if id == "" {
		c.count(ev.Type, outcomeSkipped)
		return nil
	}

	n, err := c.db.DeleteOpenCTI(ctx, c.opts.Source.ID, id)
	if err != nil {
		c.count(ev.Type, outcomeFailed)
		return fmt.Errorf("syncconsumer: xóa %s: %w", id, err)
	}
	if n == 0 {
		// Xóa một indicator ta chưa từng ghi (IP, hash...). Bình thường.
		c.count(ev.Type, outcomeSkipped)
		return nil
	}

	c.count(ev.Type, outcomeApplied)
	c.opts.Log.Info("gỡ bản ghi OpenCTI", "stix_id", id, "rows", n)
	return nil
}

// handleMerge ánh xạ định danh cũ sang entity còn lại RỒI mới ghi entity đó.
//
// Thứ tự này quan trọng: ánh xạ trước thì hàng cũ đã mang định danh mới, nên bước ghi
// tiếp theo cập nhật đúng hàng đó thay vì tạo thêm hàng thứ hai cho cùng một domain.
// Làm ngược lại sẽ để lại chính những hàng mồ côi mà bước này sinh ra để dọn.
func (c *Consumer) handleMerge(ctx context.Context, ev opencti.Event, now time.Time) error {
	to := objectID(ev.Object)
	if to == "" || len(ev.MergedFrom) == 0 {
		c.count(ev.Type, outcomeSkipped)
		return nil
	}

	n, err := c.db.MergeOpenCTI(ctx, c.opts.Source.ID, ev.MergedFrom, to)
	if err != nil {
		c.count(ev.Type, outcomeFailed)
		return fmt.Errorf("syncconsumer: gộp về %s: %w", to, err)
	}
	if n > 0 {
		c.opts.Log.Info("gộp định danh OpenCTI",
			"to", to, "from", strings.Join(ev.MergedFrom, ","), "rows", n)
	}

	return c.handleUpsert(ctx, ev, now)
}

// categoriesFor ánh xạ nhãn OpenCTI sang category.
//
// Trả nil khi không nhãn nào khớp, để tầng store dùng category mặc định của nguồn. Bỏ
// hẳn indicator không khớp nhãn sẽ vứt đi phần lớn dữ liệu của một cài đặt OpenCTI mới
// dựng, nơi chưa ai kịp gắn nhãn.
func (c *Consumer) categoriesFor(labels []string) []int16 {
	if len(c.opts.LabelCategories) == 0 || len(labels) == 0 {
		return nil
	}

	seen := make(map[int16]struct{})
	for _, l := range labels {
		for _, id := range c.opts.LabelCategories[strings.ToLower(strings.TrimSpace(l))] {
			seen[id] = struct{}{}
		}
	}
	if len(seen) == 0 {
		return nil
	}

	out := make([]int16, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	// Sắp xếp để kết quả tất định: mảng này đi thẳng vào câu lệnh SQL và vào test.
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func (c *Consumer) count(eventType, outcome string) {
	if c.opts.Metrics == nil {
		return
	}
	if eventType == "" {
		eventType = opencti.EventMessage
	}
	c.opts.Metrics.StreamEvents.WithLabelValues(eventType, outcome).Inc()
}

// maybeFlush ghi checkpoint khi đủ số sự kiện hoặc đủ lâu.
func (c *Consumer) maybeFlush(ctx context.Context, now time.Time) error {
	if c.pendingCount == 0 {
		return nil
	}
	if c.pendingCount < int64(c.opts.CheckpointEvery) && now.Sub(c.lastFlush) < c.opts.CheckpointAfter {
		return nil
	}
	return c.Flush(ctx)
}

// Flush ghi checkpoint ngay.
//
// Gọi sau khi stream đóng, trước khi thoát. Checkpoint luôn được ghi SAU khi sự kiện đã
// áp dụng xong: ghi trước rồi chết giữa chừng sẽ bỏ qua vĩnh viễn sự kiện đó.
func (c *Consumer) Flush(ctx context.Context) error {
	if c.pendingCount == 0 {
		return nil
	}
	if err := c.db.SaveStreamState(ctx,
		c.opts.Source.ID, c.opts.StreamID, c.pendingID, c.pendingAt, c.pendingCount,
	); err != nil {
		return err
	}
	c.pendingCount = 0
	c.lastFlush = c.opts.Now()
	return nil
}

// objectID lấy định danh của đối tượng, chấp nhận cả dạng stream lẫn dạng GraphQL.
func objectID(obj map[string]any) string {
	if v, ok := obj["id"].(string); ok && v != "" {
		return v
	}
	if v, ok := obj["x_opencti_id"].(string); ok {
		return v
	}
	return ""
}

// eventTime lấy dấu thời gian của sự kiện để đo độ trễ.
func eventTime(ev opencti.Event) time.Time {
	if ev.Object == nil {
		return time.Time{}
	}
	for _, k := range []string{"updated_at", "modified", "created"} {
		if s, ok := ev.Object[k].(string); ok {
			if t, err := time.Parse(time.RFC3339, s); err == nil {
				return t.UTC()
			}
		}
	}
	return time.Time{}
}

// rawLine dựng dòng thô lưu xuống L0.
//
// Ưu tiên pattern gốc của indicator: đó là thứ analyst thực sự nhìn thấy trong OpenCTI,
// và mục đích của L0 là trả lời được "vì sao domain này có ở đây" nhiều tháng sau.
func rawLine(obj map[string]any) string {
	if s, ok := obj["pattern"].(string); ok && s != "" {
		return s
	}
	if s, ok := obj["value"].(string); ok {
		return s
	}
	return ""
}
