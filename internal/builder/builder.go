// Package builder dựng bộ snapshot blocklist từ quyết định trong PostgreSQL.
//
// Đây là tầng L3 của mô hình suy dẫn: hàm thuần của L2 cộng cấu hình. Nó CHỈ đọc từ
// PostgreSQL và chỉ đọc quyết định của một lượt policy đã hoàn tất, nên không bao giờ
// dựng ra một bộ nửa cũ nửa mới (xung đột C4).
package builder

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/render"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// allFile là tên file gộp mọi category.
const allFile = "all.txt"

// Builder dựng và phát hành bộ snapshot.
type Builder struct {
	DB      *store.Store
	Store   *snapshot.Store
	Metrics *metrics.Metrics
	Log     *slog.Logger
	Format  render.Format
}

// Result là kết quả một lần dựng.
type Result struct {
	Version string
	// Skipped báo dữ liệu không đổi nên không có bộ mới nào được phát hành.
	Skipped    bool
	Categories int
	Entries    int
}

// ErrNoPolicyRun báo chưa có lượt policy nào hoàn tất.
var ErrNoPolicyRun = fmt.Errorf("builder: chưa có lượt policy nào hoàn tất")

// Build dựng một bộ snapshot đầy đủ và phát hành nếu nội dung có thay đổi.
func (b *Builder) Build(ctx context.Context, now time.Time) (Result, error) {
	format := b.Format
	if format == "" {
		format = render.FormatDomain
	}

	runID, err := b.DB.CurrentPolicyRun(ctx)
	if err != nil {
		return Result{}, err
	}
	if runID == 0 {
		return Result{}, ErrNoPolicyRun
	}

	categories, err := b.DB.Categories(ctx)
	if err != nil {
		return Result{}, err
	}

	bodies := make(map[string]render.Body, len(categories)+1)
	var union []domainname.Rule
	total := 0

	for _, cat := range categories {
		start := time.Now()

		rules, err := b.DB.BlockedRules(ctx, cat)
		if err != nil {
			return Result{}, err
		}

		body, err := render.Render(rules, format)
		if err != nil {
			return Result{}, err
		}

		name := cat + ".txt"
		bodies[name] = body
		union = append(union, rules...)
		total += body.Entries

		b.observe(name, cat, body, time.Since(start))
	}

	// all.txt gộp từ các tập đã đọc thay vì truy vấn lại: Collapse sẽ bỏ trùng lặp và
	// bỏ domain con đã bị cha phủ, nên kết quả không phụ thuộc thứ tự category.
	//
	// Đây là artifact đắt nhất của cả hệ: ở mốc 10M domain nó cỡ 200-250 MB. Nếu về
	// sau số đo cho thấy không dùng nổi, phương án dự phòng là bỏ hẳn hoặc giới hạn nó
	// ở nhóm category CTI.
	allStart := time.Now()
	allBody, err := render.Render(union, format)
	if err != nil {
		return Result{}, err
	}
	bodies[allFile] = allBody
	b.observe(allFile, "all", allBody, time.Since(allStart))

	if b.unchanged(bodies) {
		b.count("unchanged")
		b.Log.Info("dữ liệu không đổi, không dựng bộ mới",
			"policy_run", runID, "entries", total)
		return Result{Skipped: true, Categories: len(categories), Entries: total}, nil
	}

	version := snapshot.NewVersion(now, setDigest(bodies))
	res, err := b.publish(ctx, version, bodies, now)
	if err != nil {
		b.count("failed")
		return Result{}, err
	}

	b.count("published")
	b.Log.Info("đã phát hành bộ snapshot",
		"version", version, "policy_run", runID,
		"categories", len(categories), "entries", total,
		"all_entries", allBody.Entries)

	res.Categories = len(categories)
	res.Entries = total
	return res, nil
}

// unchanged so checksum của bộ sắp dựng với bộ đang phát hành.
//
// So sánh theo checksum NỘI DUNG chứ không theo thời điểm: header có chứa thời điểm
// dựng nên nếu băm cả file thì mỗi lần chạy đều "khác" và ta sẽ dựng lại vô ích.
func (b *Builder) unchanged(bodies map[string]render.Body) bool {
	m, err := b.Store.Manifest()
	if err != nil {
		return false // chưa có bộ nào, hoặc không đọc được: cứ dựng
	}
	if len(m.Lists) != len(bodies) {
		return false
	}
	for name, body := range bodies {
		entry, ok := m.Lists[name]
		if !ok || entry.ETag != body.Checksum {
			return false
		}
	}
	return true
}

func (b *Builder) publish(
	ctx context.Context, version string, bodies map[string]render.Body, now time.Time,
) (Result, error) {
	set, err := b.Store.Begin(version, now)
	if err != nil {
		return Result{}, err
	}
	// Abort là no-op sau khi Commit thành công; gọi ở đây để mọi đường thoát sớm đều
	// dọn sạch thư mục dựng dở.
	defer func() { _ = set.Abort() }()

	attrs, err := b.DB.Attributions(ctx)
	if err != nil {
		return Result{}, err
	}
	labels := make([]string, 0, len(attrs))
	for _, a := range attrs {
		set.Attribute(snapshot.Attribution{Source: a.Source, License: a.License, URL: a.URL})
		labels = append(labels, a.Label())
	}

	// Thứ tự ghi ổn định để log và lỗi dễ đối chiếu giữa các lần chạy.
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	slices.Sort(names)

	for _, name := range names {
		category := name[:len(name)-len(".txt")]
		if err := set.Add(name, render.Header{
			Category:    category,
			Attribution: labels,
		}, bodies[name]); err != nil {
			return Result{}, err
		}
	}

	if _, err := set.Commit(); err != nil {
		return Result{}, err
	}

	if removed, err := b.Store.Prune(); err != nil {
		// Dọn bộ cũ hỏng không làm hỏng lần phát hành: bộ mới đã có hiệu lực rồi.
		b.Log.Warn("dọn bộ snapshot cũ thất bại", "err", err)
	} else if len(removed) > 0 {
		b.Log.Info("đã dọn bộ snapshot cũ", "versions", removed)
	}

	return Result{Version: version}, nil
}

// setDigest băm checksum của mọi file trong bộ, theo thứ tự tên file.
//
// Dùng làm hậu tố version: hai bộ có nội dung khác nhau không bao giờ trùng version,
// kể cả khi dựng trong cùng một giây.
func setDigest(bodies map[string]render.Body) string {
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	slices.Sort(names)

	h := sha256.New()
	for _, name := range names {
		h.Write([]byte(name))
		h.Write([]byte{0})
		h.Write([]byte(bodies[name].Checksum))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (b *Builder) observe(name, category string, body render.Body, d time.Duration) {
	if b.Metrics == nil {
		return
	}
	const tenant = "public"
	b.Metrics.SnapshotBuildSec.WithLabelValues(tenant, category).Observe(d.Seconds())
	b.Metrics.SnapshotEntries.WithLabelValues(tenant, category).Set(float64(body.Entries))
	b.Metrics.SnapshotBytes.WithLabelValues(tenant, category).Set(float64(len(body.Bytes)))
}

func (b *Builder) count(outcome string) {
	if b.Metrics != nil {
		b.Metrics.SnapshotPublishes.WithLabelValues(outcome).Inc()
	}
}
