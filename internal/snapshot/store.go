// Package snapshot phát hành các bộ blocklist theo mô hình nguyên tử ở mức BỘ.
//
// Publish từng file một sẽ để lộ trạng thái nửa vời: malware.txt đã cập nhật, ads.txt
// chưa, manifest.json nói version X, và client tải về một bộ không nhất quán (xung đột
// E2). Ở đây cả bộ được ghi vào snapshots/{version}/ rồi con trỏ current mới được đổi
// bằng MỘT thao tác duy nhất. Hoặc cả bộ có hiệu lực, hoặc không có gì đổi.
//
// Con trỏ current là một file văn bản chứa tên version, không phải symlink: symlink cần
// quyền đặc biệt trên Windows và việc thay thế nó không nguyên tử ở đó. Ghi file qua
// temp + rename thì nguyên tử trên cả hai nền tảng.
//
// Nhờ vậy rollback chỉ là ghi lại con trỏ, không phải dựng lại gì.
package snapshot

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/render"
)

const (
	currentFile  = "current"
	manifestName = "manifest.json"
	tmpPrefix    = ".building-"

	// gzipSuffix là đuôi của bản nén đặt cạnh mỗi file.
	gzipSuffix = ".gz"

	// tenantDir là thư mục con chứa file riêng của từng tenant.
	tenantDir = "t"
)

// ErrNoCurrent báo chưa có bộ nào được phát hành.
var ErrNoCurrent = errors.New("chưa có snapshot nào được phát hành")

// Store quản lý thư mục gốc chứa các bộ snapshot.
type Store struct {
	root string
	keep int
}

// NewStore mở (và tạo nếu cần) thư mục gốc. keep là số bộ cũ giữ lại để rollback.
func NewStore(root string, keep int) (*Store, error) {
	if keep < 1 {
		return nil, fmt.Errorf("snapshot: keep = %d, phải >= 1 để còn bản rollback", keep)
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("snapshot: tạo thư mục gốc: %w", err)
	}
	return &Store{root: filepath.Clean(root), keep: keep}, nil
}

// Root trả về thư mục gốc.
func (s *Store) Root() string { return s.root }

// ListEntry mô tả một file trong manifest.
type ListEntry struct {
	ETag    string `json:"etag"`
	Entries int    `json:"entries"`
	Bytes   int64  `json:"bytes"`
	// GzipBytes là kích thước bản nén phục vụ sẵn cạnh file gốc.
	GzipBytes int64 `json:"gzip_bytes,omitempty"`

	// SameAs trỏ tới một file khác trong cùng bộ khi nội dung trùng khớp hoàn toàn.
	//
	// Phần lớn tenant không có override nào, nên file của họ giống hệt bản dùng chung.
	// Ghi ra N bản sao của một file 200 MB là lãng phí thuần túy; ở đây chỉ ghi con
	// trỏ và để tầng phục vụ đọc file gốc.
	SameAs string `json:"same_as,omitempty"`
}

// Manifest là nội dung manifest.json.
type Manifest struct {
	Version     string               `json:"version"`
	GeneratedAt string               `json:"generated_at"`
	Lists       map[string]ListEntry `json:"lists"`
	Attribution []Attribution        `json:"attribution,omitempty"`

	// Tenants chứa các bộ file riêng, khóa theo slug tenant. Tenant mặc định nằm ở
	// Lists chứ không ở đây: các URL phẳng của claude_rm.md chính là tenant đó.
	Tenants map[string]TenantLists `json:"tenants,omitempty"`
}

// TenantLists là bộ file của một tenant.
type TenantLists struct {
	Lists map[string]ListEntry `json:"lists"`
}

// Attribution ghi nhận nguồn và điều khoản license của nó. Bắt buộc có: hệ tái phát
// hành list dẫn xuất từ nhiều nguồn có điều khoản riêng.
type Attribution struct {
	Source  string `json:"source"`
	License string `json:"license,omitempty"`
	URL     string `json:"url,omitempty"`
}

// Set là một bộ đang được dựng. Chưa có tác dụng gì cho tới khi Commit.
type Set struct {
	store   *Store
	version string
	tmpDir  string
	now     time.Time

	lists       map[string]ListEntry
	tenants     map[string]map[string]ListEntry
	attribution []Attribution
	committed   bool

	// byChecksum ánh xạ checksum -> đường dẫn file đã ghi, để nội dung trùng nhau
	// dùng chung một file trên đĩa.
	byChecksum map[string]string
}

// Begin mở một bộ mới. Nội dung được ghi vào thư mục tạm cho tới khi Commit.
func (s *Store) Begin(version string, now time.Time) (*Set, error) {
	if version == "" || strings.ContainsAny(version, `/\`) {
		return nil, fmt.Errorf("snapshot: version không hợp lệ %q", version)
	}

	tmpDir := filepath.Join(s.root, tmpPrefix+version)
	// Dọn tàn dư của một lần dựng hỏng trước đó.
	if err := os.RemoveAll(tmpDir); err != nil {
		return nil, fmt.Errorf("snapshot: dọn thư mục dựng: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return nil, fmt.Errorf("snapshot: tạo thư mục dựng: %w", err)
	}

	return &Set{
		store:      s,
		version:    version,
		tmpDir:     tmpDir,
		now:        now,
		lists:      map[string]ListEntry{},
		tenants:    map[string]map[string]ListEntry{},
		byChecksum: map[string]string{},
	}, nil
}

// Version trả về tên version của bộ đang dựng.
func (set *Set) Version() string { return set.version }

// Attribute ghi nhận một nguồn vào manifest.
func (set *Set) Attribute(a Attribution) { set.attribution = append(set.attribution, a) }

// Add ghi một file vào bộ cho tenant mặc định. name là tên file, ví dụ "malware.txt".
func (set *Set) Add(name string, h render.Header, b render.Body) error {
	entry, err := set.write("", name, h, b)
	if err != nil {
		return err
	}
	set.lists[name] = entry
	return nil
}

// AddTenant ghi một file vào bộ cho một tenant cụ thể.
//
// Nội dung trùng với một file đã ghi sẽ KHÔNG được ghi lại: mục manifest chỉ trỏ tới
// file kia qua SameAs. Phần lớn tenant không có override nào nên file của họ giống hệt
// bản dùng chung, và ghi ra N bản sao của một file 200 MB là lãng phí thuần túy.
func (set *Set) AddTenant(slug, name string, h render.Header, b render.Body) error {
	if !safeSegment(slug) {
		return fmt.Errorf("snapshot: slug tenant không hợp lệ %q", slug)
	}

	entry, err := set.write(tenantDir+"/"+slug, name, h, b)
	if err != nil {
		return err
	}
	if set.tenants[slug] == nil {
		set.tenants[slug] = map[string]ListEntry{}
	}
	set.tenants[slug][name] = entry
	return nil
}

// write ghi một file (kèm bản nén) vào dir bên trong bộ đang dựng.
func (set *Set) write(dir, name string, h render.Header, b render.Body) (ListEntry, error) {
	if !safeSegment(name) {
		return ListEntry{}, fmt.Errorf("snapshot: tên file không hợp lệ %q", name)
	}

	rel := name
	if dir != "" {
		rel = dir + "/" + name
	}

	// Nội dung y hệt một file đã ghi: chỉ trỏ tới nó.
	if existing, ok := set.byChecksum[b.Checksum]; ok {
		return ListEntry{
			ETag: b.Checksum, Entries: b.Entries,
			SameAs: existing,
		}, nil
	}

	h.Version = set.version
	h.GeneratedAt = set.now.UTC().Format(time.RFC3339)
	h.Entries = b.Entries
	h.Checksum = b.Checksum

	full := filepath.Join(set.tmpDir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return ListEntry{}, fmt.Errorf("snapshot: tạo thư mục cho %s: %w", rel, err)
	}

	f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return ListEntry{}, fmt.Errorf("snapshot: tạo %s: %w", rel, err)
	}

	n, err := render.WriteTo(f, h, b)
	if err != nil {
		f.Close()
		return ListEntry{}, fmt.Errorf("snapshot: ghi %s: %w", rel, err)
	}
	// fsync trước khi coi là xong: đầy đĩa hoặc mất điện giữa chừng phải hỏng ở đây,
	// không phải sau khi con trỏ current đã trỏ vào bộ này (xung đột E4).
	if err := f.Sync(); err != nil {
		f.Close()
		return ListEntry{}, fmt.Errorf("snapshot: fsync %s: %w", rel, err)
	}
	if err := f.Close(); err != nil {
		return ListEntry{}, fmt.Errorf("snapshot: đóng %s: %w", rel, err)
	}

	gzBytes, err := set.writeGzip(rel, h, b)
	if err != nil {
		return ListEntry{}, err
	}

	set.byChecksum[b.Checksum] = rel

	// ETag là hash NỘI DUNG, không phải version, nên rollback không làm ETag nhảy về
	// một giá trị chưa client nào từng thấy (xung đột E3).
	return ListEntry{
		ETag: b.Checksum, Entries: b.Entries, Bytes: n, GzipBytes: gzBytes,
	}, nil
}

// safeSegment chặn dấu gạch chéo và đường dẫn tương đối trong tên do bên ngoài cung cấp.
func safeSegment(s string) bool {
	return s != "" && s != "." && s != ".." &&
		!strings.ContainsAny(s, `/\`)
}

// writeGzip ghi thêm bản nén cạnh file gốc.
//
// Nén sẵn lúc dựng chứ không nén theo từng request: all.txt ở mốc 10M domain cỡ
// 200-250 MB, nén lại cho mỗi client là không khả thi. Dựng một lần rồi phục vụ nhiều
// lần thì chi phí nằm đúng chỗ.
func (set *Set) writeGzip(rel string, h render.Header, b render.Body) (int64, error) {
	name := rel + gzipSuffix
	path := filepath.Join(set.tmpDir, filepath.FromSlash(name))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return 0, fmt.Errorf("snapshot: tạo %s: %w", name, err)
	}
	defer f.Close()

	counter := &countingWriter{w: f}
	zw, err := gzip.NewWriterLevel(counter, gzip.BestSpeed)
	if err != nil {
		return 0, fmt.Errorf("snapshot: khởi tạo gzip: %w", err)
	}

	if _, err := render.WriteTo(zw, h, b); err != nil {
		return 0, fmt.Errorf("snapshot: ghi %s: %w", name, err)
	}
	if err := zw.Close(); err != nil {
		return 0, fmt.Errorf("snapshot: đóng gzip: %w", err)
	}
	if err := f.Sync(); err != nil {
		return 0, fmt.Errorf("snapshot: fsync %s: %w", name, err)
	}
	return counter.n, nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Commit hoàn tất bộ và đổi con trỏ current sang nó.
func (set *Set) Commit() (Manifest, error) {
	if set.committed {
		return Manifest{}, errors.New("snapshot: bộ đã commit")
	}
	if len(set.lists) == 0 {
		return Manifest{}, errors.New("snapshot: bộ rỗng, không publish")
	}

	m := Manifest{
		Version:     set.version,
		GeneratedAt: set.now.UTC().Format(time.RFC3339),
		Lists:       set.lists,
		Attribution: set.attribution,
	}
	if len(set.tenants) > 0 {
		m.Tenants = make(map[string]TenantLists, len(set.tenants))
		for slug, lists := range set.tenants {
			m.Tenants[slug] = TenantLists{Lists: lists}
		}
	}

	raw, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: dựng manifest: %w", err)
	}
	raw = append(raw, '\n')

	if err := writeFileSync(filepath.Join(set.tmpDir, manifestName), raw); err != nil {
		return Manifest{}, err
	}

	finalDir := filepath.Join(set.store.root, set.version)
	if err := os.RemoveAll(finalDir); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: dọn thư mục đích: %w", err)
	}
	if err := os.Rename(set.tmpDir, finalDir); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: chuyển bộ vào vị trí: %w", err)
	}

	// Chỉ tới dòng này bộ mới có hiệu lực. Nếu tiến trình chết TRƯỚC nó, thư mục
	// version đã tồn tại nhưng chưa ai trỏ tới — vô hại, Prune sẽ dọn.
	if err := set.store.setCurrent(set.version); err != nil {
		return Manifest{}, err
	}

	set.committed = true
	return m, nil
}

// Abort bỏ bộ đang dựng. An toàn khi gọi nhiều lần, kể cả sau Commit.
func (set *Set) Abort() error {
	if set.committed {
		return nil
	}
	return os.RemoveAll(set.tmpDir)
}

func (s *Store) setCurrent(version string) error {
	return writeFileSync(filepath.Join(s.root, currentFile), []byte(version+"\n"))
}

// writeFileSync ghi qua file tạm rồi rename: người đọc không bao giờ thấy file dở dang.
func writeFileSync(path string, data []byte) error {
	tmp := path + ".tmp"

	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("snapshot: tạo %s: %w", tmp, err)
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return fmt.Errorf("snapshot: ghi %s: %w", tmp, err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("snapshot: fsync %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("snapshot: đóng %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("snapshot: rename %s: %w", path, err)
	}
	return nil
}

// Current trả về version đang được phát hành.
func (s *Store) Current() (string, error) {
	raw, err := os.ReadFile(filepath.Join(s.root, currentFile))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoCurrent
	}
	if err != nil {
		return "", fmt.Errorf("snapshot: đọc con trỏ current: %w", err)
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", ErrNoCurrent
	}
	return v, nil
}

// Path trả về đường dẫn tới một file trong bộ đang phát hành.
func (s *Store) Path(name string) (string, error) {
	v, err := s.Current()
	if err != nil {
		return "", err
	}
	return filepath.Join(s.root, v, name), nil
}

// Manifest đọc manifest của bộ đang phát hành.
func (s *Store) Manifest() (Manifest, error) {
	p, err := s.Path(manifestName)
	if err != nil {
		return Manifest{}, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return Manifest{}, fmt.Errorf("snapshot: đọc manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return Manifest{}, fmt.Errorf("snapshot: phân tích manifest: %w", err)
	}
	return m, nil
}

// Versions liệt kê các bộ đã dựng xong, mới nhất trước (tên version sắp được theo thứ
// tự từ vựng vì bắt đầu bằng dấu thời gian).
func (s *Store) Versions() ([]string, error) {
	entries, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("snapshot: đọc thư mục gốc: %w", err)
	}

	var out []string
	for _, e := range entries {
		if !e.IsDir() || strings.HasPrefix(e.Name(), tmpPrefix) {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// Rollback trỏ current về một bộ cũ. Chỉ là ghi lại con trỏ — không dựng lại gì.
func (s *Store) Rollback(version string) error {
	dir := filepath.Join(s.root, version)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return fmt.Errorf("snapshot: không có bộ %q để rollback", version)
	}
	if _, err := os.Stat(filepath.Join(dir, manifestName)); err != nil {
		return fmt.Errorf("snapshot: bộ %q thiếu manifest, không rollback vào bản dở dang", version)
	}
	return s.setCurrent(version)
}

// Prune xóa các bộ cũ, giữ lại keep bộ mới nhất và luôn giữ bộ đang phát hành.
func (s *Store) Prune() ([]string, error) {
	versions, err := s.Versions()
	if err != nil {
		return nil, err
	}

	current, err := s.Current()
	if err != nil && !errors.Is(err, ErrNoCurrent) {
		return nil, err
	}

	var removed []string
	for i, v := range versions {
		if i < s.keep || v == current {
			continue
		}
		if err := os.RemoveAll(filepath.Join(s.root, v)); err != nil {
			return removed, fmt.Errorf("snapshot: xóa bộ %s: %w", v, err)
		}
		removed = append(removed, v)
	}
	return removed, nil
}

// NewVersion sinh tên version từ thời điểm và checksum tổng của bộ.
func NewVersion(now time.Time, digest string) string {
	digest = strings.TrimPrefix(digest, "sha256:")
	if len(digest) > 8 {
		digest = digest[:8]
	}
	return now.UTC().Format("2006-01-02T15-04-05Z") + "-" + digest
}

// ErrNotInSet báo file không có trong bộ đang phát hành.
var ErrNotInSet = errors.New("file không có trong bộ snapshot")

// FileRef là kết quả tra cứu một file trong bộ đang phát hành.
type FileRef struct {
	// Path là đường dẫn tuyệt đối tới file .txt (đã đi theo SameAs nếu có).
	Path  string
	Entry ListEntry
}

// GzipPath là đường dẫn tới bản nén dựng sẵn.
func (f FileRef) GzipPath() string { return f.Path + gzipSuffix }

// Lookup tìm một file trong bộ đang phát hành. tenant rỗng nghĩa là tenant mặc định.
//
// Tự đi theo con trỏ SameAs, nên bên gọi không cần biết file của tenant có phải bản
// dùng chung hay không.
func (s *Store) Lookup(tenant, name string) (FileRef, error) {
	m, err := s.Manifest()
	if err != nil {
		return FileRef{}, err
	}
	version, err := s.Current()
	if err != nil {
		return FileRef{}, err
	}

	var (
		entry ListEntry
		ok    bool
		rel   string
	)
	if tenant == "" {
		entry, ok = m.Lists[name]
		rel = name
	} else {
		t, found := m.Tenants[tenant]
		if found {
			entry, ok = t.Lists[name]
		}
		rel = tenantDir + "/" + tenant + "/" + name
	}
	if !ok {
		return FileRef{}, fmt.Errorf("%w: %s", ErrNotInSet, name)
	}

	if entry.SameAs != "" {
		rel = entry.SameAs
	}

	// Chốt chặn cuối: đường dẫn phải nằm trong thư mục của bộ. SameAs đến từ manifest
	// trên đĩa, và một file bị sửa tay không được biến thành đường thoát ra ngoài.
	root := filepath.Join(s.root, version)
	full := filepath.Join(root, filepath.FromSlash(rel))
	if !strings.HasPrefix(full, root+string(filepath.Separator)) {
		return FileRef{}, fmt.Errorf("%w: đường dẫn thoát khỏi bộ: %s", ErrNotInSet, rel)
	}

	return FileRef{Path: full, Entry: entry}, nil
}
