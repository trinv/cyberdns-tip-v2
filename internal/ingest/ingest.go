// Package ingest điều phối một lần import của một nguồn feed.
//
// Toàn bộ quy tắc fail-closed nằm ở đây: mọi đường thoát lỗi đều KHÔNG ghi gì vào L0/L1
// và luôn đóng bản ghi audit với lý do cụ thể. Không bao giờ có trạng thái "import một
// nửa".
package ingest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/feed"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// Ingestor chạy import cho các nguồn.
type Ingestor struct {
	DB      *store.Store
	Fetcher *feed.Fetcher
	Metrics *metrics.Metrics
	Log     *slog.Logger
}

// Result là kết quả một lần import.
type Result struct {
	Source     string
	Status     string
	Accepted   int
	Rejected   int
	Added      int
	Removed    int
	NotChanged bool
}

// One chạy trọn một lần import cho một nguồn.
//
// Trả về lỗi khi import bị từ chối. Bên gọi nên ghi log rồi đi tiếp sang nguồn khác:
// một nguồn hỏng không được làm dừng cả chu kỳ.
func (in *Ingestor) One(ctx context.Context, src store.Source, now time.Time) (Result, error) {
	res := Result{Source: src.Name}
	start := time.Now()

	fs := feed.Source{
		ID:               fmt.Sprint(src.ID),
		Name:             src.Name,
		URL:              src.URL,
		MaxResponseBytes: src.MaxResponseBytes,
		MaxChangeRatio:   src.MaxChangeRatio,
	}

	prev, err := in.DB.LastSuccessfulImport(ctx, src.ID)
	if err != nil {
		return res, err
	}

	importID, err := in.DB.BeginImport(ctx, src.ID)
	if err != nil {
		return res, err
	}

	// fail đóng bản ghi audit rồi trả lỗi. Bản ghi mắc kẹt ở trạng thái 'running' sẽ
	// khiến LastSuccessfulImport bỏ sót và mọi cảnh báo feed stale mất tác dụng.
	fail := func(status string, cause error) (Result, error) {
		res.Status = status
		_ = in.DB.FinishImport(ctx, importID, store.ImportResult{
			Status: status, ErrorMessage: cause.Error(),
		})
		in.mark(src.Name, false)
		return res, cause
	}

	resp, err := in.Fetcher.Fetch(ctx, fs, feed.Conditional{
		ETag: prev.ETag, LastModified: prev.LastModified,
	})
	if errors.Is(err, feed.ErrNotModified) {
		res.Status, res.NotChanged = "unchanged", true
		_ = in.DB.FinishImport(ctx, importID, store.ImportResult{
			Status: "unchanged", ETag: prev.ETag, LastModified: prev.LastModified,
			FeedHash: prev.FeedHash, Accepted: prev.Accepted,
		})
		in.mark(src.Name, true)
		in.Log.Debug("feed không đổi", "source", src.Name)
		return res, nil
	}
	if err != nil {
		return fail("failed", fmt.Errorf("tải feed: %w", err))
	}

	var records []store.Record
	stats, parseErr := feed.Parse(resp.Body, func(rule domainname.Rule, raw string) error {
		// raw_hash băm CHÍNH DÒNG đó, không phải cả feed: cả feed đã có feed_hash
		// riêng, và gọi resp.Hash() ở đây còn cho ra hash của phần mới đọc dở.
		records = append(records, store.Record{
			Rule: rule, RawLine: raw, RawHash: hashLine(raw),
		})
		return nil
	})
	hash := resp.Hash()
	bytes := resp.Bytes()

	// Đóng body trả về lỗi cắt cụt: một feed tải được một nửa trông y hệt một feed
	// vừa gỡ bỏ một nửa số domain.
	closeErr := resp.Body.Close()

	if parseErr != nil {
		return fail("rejected", fmt.Errorf("phân tích feed: %w", parseErr))
	}
	if closeErr != nil {
		return fail("rejected", fmt.Errorf("phản hồi không toàn vẹn: %w", closeErr))
	}

	res.Accepted, res.Rejected = stats.Accepted, stats.Rejected
	in.observe(src.Name, stats, bytes)

	if err := feed.Validate(fs, stats, prev.Accepted); err != nil {
		return fail("rejected", err)
	}

	// Nội dung y hệt lần trước: không cần ghi lại gì cả.
	if prev.Found && prev.FeedHash == hash {
		res.Status, res.NotChanged = "unchanged", true
		_ = in.DB.FinishImport(ctx, importID, store.ImportResult{
			Status: "unchanged", FeedHash: hash, ETag: resp.ETag,
			LastModified: resp.LastModified, HTTPStatus: resp.Status,
			Bytes: bytes, Total: stats.Lines, Accepted: stats.Accepted,
		})
		in.mark(src.Name, true)
		return res, nil
	}

	applied, err := in.DB.Apply(ctx, src, importID, hash, records, now)
	if err != nil {
		return fail("failed", err)
	}
	res.Added, res.Removed = applied.Added, applied.Removed
	res.Status = "completed"

	if err := in.DB.FinishImport(ctx, importID, store.ImportResult{
		Status: "completed", FeedHash: hash, ETag: resp.ETag,
		LastModified: resp.LastModified, HTTPStatus: resp.Status, Bytes: bytes,
		Total: stats.Lines, Accepted: stats.Accepted, Rejected: stats.Rejected,
		Added: applied.Added, Updated: applied.Updated, Removed: applied.Removed,
	}); err != nil {
		return res, err
	}

	in.mark(src.Name, true)
	if in.Metrics != nil {
		in.Metrics.FeedDurationSec.WithLabelValues(src.Name, "total").
			Observe(time.Since(start).Seconds())
	}

	in.Log.Info("import xong",
		"source", src.Name, "accepted", stats.Accepted, "rejected", stats.Rejected,
		"added", applied.Added, "removed", applied.Removed,
		"duration", time.Since(start).Round(time.Millisecond))
	return res, nil
}

// All chạy import cho mọi nguồn direct đang bật.
//
// Một nguồn hỏng không làm dừng các nguồn còn lại: cô lập sự cố theo nguồn là điều kiện
// để một feed bị chiếm quyền không kéo sập cả chu kỳ.
func (in *Ingestor) All(ctx context.Context, now time.Time) ([]Result, error) {
	sources, err := in.DB.EnabledSources(ctx, "direct")
	if err != nil {
		return nil, err
	}

	results := make([]Result, 0, len(sources))
	for _, src := range sources {
		if ctx.Err() != nil {
			return results, ctx.Err()
		}
		// Khởi tạo nhãn metric ngay: nếu không, cảnh báo "feed_up == 0" sẽ im lặng
		// đúng với nguồn chưa từng chạy thành công lần nào.
		if in.Metrics != nil {
			in.Metrics.InitSource(src.Name)
		}

		r, err := in.One(ctx, src, now)
		if err != nil {
			in.Log.Error("import thất bại", "source", src.Name, "err", err)
		}
		results = append(results, r)
	}
	return results, nil
}

func (in *Ingestor) mark(source string, ok bool) {
	if in.Metrics == nil {
		return
	}
	if ok {
		in.Metrics.FeedUp.WithLabelValues(source).Set(1)
		in.Metrics.FeedLastSuccessTS.WithLabelValues(source).Set(float64(time.Now().Unix()))
		return
	}
	in.Metrics.FeedUp.WithLabelValues(source).Set(0)
}

func (in *Ingestor) observe(source string, stats feed.Stats, bytes int64) {
	if in.Metrics == nil {
		return
	}
	in.Metrics.FeedDownloadBytes.WithLabelValues(source).Add(float64(bytes))
	in.Metrics.FeedRecords.WithLabelValues(source, "accepted").Add(float64(stats.Accepted))
	in.Metrics.FeedRecords.WithLabelValues(source, "rejected").Add(float64(stats.Rejected))
	for reason, n := range stats.RejectReasons {
		in.Metrics.FeedParseErrors.WithLabelValues(source, reason).Add(float64(n))
	}
}

// hashLine băm một dòng thô, dùng cho cột raw_hash của bằng chứng L0.
func hashLine(line string) string {
	sum := sha256.Sum256([]byte(line))
	return "sha256:" + hex.EncodeToString(sum[:])
}
