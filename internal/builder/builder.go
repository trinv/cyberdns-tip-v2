// Package builder dựng bộ snapshot blocklist từ quyết định trong PostgreSQL.
//
// Đây là tầng L3 của mô hình suy dẫn: hàm thuần của L2 cộng cấu hình tenant. Nó CHỈ
// đọc từ PostgreSQL và chỉ đọc quyết định của một lượt policy đã hoàn tất, nên không
// bao giờ dựng ra một bộ nửa cũ nửa mới (xung đột C4).
//
// Phần đắt tiền — đọc tập rule BLOCK của từng category — làm MỘT LẦN và dùng chung cho
// mọi tenant. Khác biệt giữa các tenant chỉ là phép toán tập hợp rẻ tiền bên trên.
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

const (
	// allFile là tên file gộp mọi category mà tenant đăng ký.
	allFile = "all.txt"
	// allowFile là file ngoại lệ, nạp vào cấu hình allowlist của Blocky.
	allowFile = "allowlist.txt"
)

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
	Tenants    int
	Categories int
	Entries    int
}

// ErrNoPolicyRun báo chưa có lượt policy nào hoàn tất.
var ErrNoPolicyRun = fmt.Errorf("builder: chưa có lượt policy nào hoàn tất")

// file là một file đã render, chờ ghi.
type file struct {
	tenant string // slug; rỗng nghĩa là tenant mặc định
	name   string
	body   render.Body
}

// key là khóa nhận diện file trong manifest.
func (f file) key() string {
	if f.tenant == "" {
		return f.name
	}
	return "t/" + f.tenant + "/" + f.name
}

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

	// Đọc tập rule BLOCK một lần cho mỗi category; mọi tenant dùng chung.
	base := make(map[string][]domainname.Rule, len(categories))
	for _, cat := range categories {
		rules, err := b.DB.BlockedRules(ctx, cat)
		if err != nil {
			return Result{}, err
		}
		base[cat] = rules
	}

	tenants, err := b.DB.Tenants(ctx, now)
	if err != nil {
		return Result{}, err
	}
	if len(tenants) == 0 {
		return Result{}, fmt.Errorf("builder: không có tenant nào đang bật")
	}

	var files []file
	total := 0
	for _, t := range tenants {
		tf, entries, err := b.buildTenant(t, base, format)
		if err != nil {
			return Result{}, err
		}
		files = append(files, tf...)
		if t.IsDefault {
			total = entries
		}
	}

	if b.unchanged(files) {
		b.count("unchanged")
		b.Log.Info("dữ liệu không đổi, không dựng bộ mới",
			"policy_run", runID, "tenants", len(tenants), "entries", total)
		return Result{Skipped: true, Tenants: len(tenants),
			Categories: len(categories), Entries: total}, nil
	}

	version := snapshot.NewVersion(now, setDigest(files))
	if err := b.publish(ctx, version, files, now); err != nil {
		b.count("failed")
		return Result{}, err
	}

	b.count("published")
	b.Log.Info("đã phát hành bộ snapshot",
		"version", version, "policy_run", runID,
		"tenants", len(tenants), "files", len(files), "entries", total)

	return Result{Version: version, Tenants: len(tenants),
		Categories: len(categories), Entries: total}, nil
}

// buildTenant render mọi file của một tenant. Trả về số dòng của denylist.
func (b *Builder) buildTenant(
	t store.Tenant, base map[string][]domainname.Rule, format render.Format,
) ([]file, int, error) {
	slug := t.Slug
	if t.IsDefault {
		// Tenant mặc định phục vụ các URL phẳng của claude_rm.md, nên file của nó nằm
		// ở gốc bộ chứ không nằm trong thư mục tenant.
		slug = ""
	}
	if t.OutputFormat != "" && render.Format(t.OutputFormat).Valid() {
		format = render.Format(t.OutputFormat)
	}

	var (
		files []file
		union []domainname.Rule
		total int
	)

	for _, cat := range t.Categories {
		rules, ok := base[cat]
		if !ok {
			continue
		}

		effective := applyOverrides(rules, t, cat)
		start := time.Now()
		body, err := render.Render(effective, format)
		if err != nil {
			return nil, 0, err
		}

		files = append(files, file{tenant: slug, name: cat + ".txt", body: body})
		union = append(union, effective...)
		total += body.Entries
		b.observe(t.Slug, cat, body, time.Since(start))
	}

	allBody, err := render.Render(union, format)
	if err != nil {
		return nil, 0, err
	}
	files = append(files, file{tenant: slug, name: allFile, body: allBody})
	b.observe(t.Slug, "all", allBody, 0)

	// File ngoại lệ. Luôn phát hành kể cả khi rỗng, để URL allowlist của tenant không
	// bao giờ trả 404 — một URL lúc có lúc không sẽ làm Blocky báo lỗi nạp danh sách.
	allowBody, err := render.Render(t.AllowRules, format)
	if err != nil {
		return nil, 0, err
	}
	files = append(files, file{tenant: slug, name: allowFile, body: allowBody})

	return files, total, nil
}

// applyOverrides áp allowlist và denylist của tenant lên tập rule dùng chung.
//
// Allowlist ở đây chỉ loại các rule KHỚP ĐÚNG. Trường hợp domain nằm dưới một rule cha
// wildcard không giải quyết được bằng cách bỏ dòng — gỡ rule cha sẽ mở toang cả nhánh.
// Đó là lý do tenant còn nhận một file allowlist riêng (xung đột D2).
func applyOverrides(base []domainname.Rule, t store.Tenant, category string) []domainname.Rule {
	out := make([]domainname.Rule, 0, len(base))
	for _, r := range base {
		if !t.Allow.Empty() && t.Allow.Match(r.Domain) {
			continue
		}
		out = append(out, r)
	}

	// Denylist khóa rỗng áp cho mọi category tenant đăng ký.
	out = append(out, t.Deny[""]...)
	out = append(out, t.Deny[category]...)
	return out
}

// unchanged so checksum của bộ sắp dựng với bộ đang phát hành.
//
// So theo checksum NỘI DUNG chứ không theo thời điểm: header chứa thời điểm dựng nên
// nếu băm cả file thì mỗi lần chạy đều "khác" và ta sẽ dựng lại vô ích.
func (b *Builder) unchanged(files []file) bool {
	m, err := b.Store.Manifest()
	if err != nil {
		return false // chưa có bộ nào, hoặc không đọc được: cứ dựng
	}

	current := map[string]string{}
	for name, e := range m.Lists {
		current[name] = e.ETag
	}
	for slug, t := range m.Tenants {
		for name, e := range t.Lists {
			current["t/"+slug+"/"+name] = e.ETag
		}
	}

	if len(current) != len(files) {
		return false
	}
	for _, f := range files {
		if current[f.key()] != f.body.Checksum {
			return false
		}
	}
	return true
}

func (b *Builder) publish(ctx context.Context, version string, files []file, now time.Time) error {
	set, err := b.Store.Begin(version, now)
	if err != nil {
		return err
	}
	// Abort là no-op sau khi Commit thành công; gọi ở đây để mọi đường thoát sớm đều
	// dọn sạch thư mục dựng dở.
	defer func() { _ = set.Abort() }()

	attrs, err := b.DB.Attributions(ctx)
	if err != nil {
		return err
	}
	labels := make([]string, 0, len(attrs))
	for _, a := range attrs {
		set.Attribute(snapshot.Attribution{Source: a.Source, License: a.License, URL: a.URL})
		labels = append(labels, a.Label())
	}

	// Thứ tự ghi ổn định để log và lỗi dễ đối chiếu, và để phép khử trùng lặp theo
	// nội dung luôn chọn cùng một file làm bản gốc.
	ordered := slices.Clone(files)
	slices.SortFunc(ordered, func(a, b file) int {
		if a.tenant != b.tenant {
			// Tenant mặc định (slug rỗng) đứng trước, nên nó là bản gốc mà các tenant
			// trùng nội dung trỏ tới.
			return len(a.tenant) - len(b.tenant)
		}
		if a.name != b.name {
			if a.name < b.name {
				return -1
			}
			return 1
		}
		return 0
	})

	for _, f := range ordered {
		h := render.Header{Attribution: labels}
		if f.tenant == "" {
			err = set.Add(f.name, h, f.body)
		} else {
			err = set.AddTenant(f.tenant, f.name, h, f.body)
		}
		if err != nil {
			return err
		}
	}

	if _, err := set.Commit(); err != nil {
		return err
	}

	if removed, err := b.Store.Prune(); err != nil {
		// Dọn bộ cũ hỏng không làm hỏng lần phát hành: bộ mới đã có hiệu lực rồi.
		b.Log.Warn("dọn bộ snapshot cũ thất bại", "err", err)
	} else if len(removed) > 0 {
		b.Log.Info("đã dọn bộ snapshot cũ", "versions", removed)
	}
	return nil
}

// setDigest băm checksum của mọi file trong bộ, theo thứ tự khóa.
//
// Dùng làm hậu tố version: hai bộ có nội dung khác nhau không bao giờ trùng version,
// kể cả khi dựng trong cùng một giây.
func setDigest(files []file) string {
	keys := make([]string, 0, len(files))
	sums := make(map[string]string, len(files))
	for _, f := range files {
		keys = append(keys, f.key())
		sums[f.key()] = f.body.Checksum
	}
	slices.Sort(keys)

	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(sums[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (b *Builder) observe(tenant, category string, body render.Body, d time.Duration) {
	if b.Metrics == nil {
		return
	}
	if d > 0 {
		b.Metrics.SnapshotBuildSec.WithLabelValues(tenant, category).Observe(d.Seconds())
	}
	b.Metrics.SnapshotEntries.WithLabelValues(tenant, category).Set(float64(body.Entries))
	b.Metrics.SnapshotBytes.WithLabelValues(tenant, category).Set(float64(len(body.Bytes)))
}

func (b *Builder) count(outcome string) {
	if b.Metrics != nil {
		b.Metrics.SnapshotPublishes.WithLabelValues(outcome).Inc()
	}
}
