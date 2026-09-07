package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/render"
)

var testNow = time.Date(2026, 9, 7, 3, 0, 0, 0, time.UTC)

func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	return s
}

func body(t *testing.T, ds ...string) render.Body {
	t.Helper()
	rules := make([]domainname.Rule, len(ds))
	for i, d := range ds {
		rules[i] = domainname.Rule{Domain: d, MatchType: domainname.Exact}
	}
	b, err := render.Render(rules, render.FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	return b
}

// publish dựng và commit một bộ đủ hai file.
func publish(t *testing.T, s *Store, version string, malware, ads []string) Manifest {
	t.Helper()

	set, err := s.Begin(version, testNow)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	defer set.Abort()

	if err := set.Add("malware.txt", render.Header{Category: "malware"}, body(t, malware...)); err != nil {
		t.Fatalf("Add malware: %v", err)
	}
	if err := set.Add("ads.txt", render.Header{Category: "ads"}, body(t, ads...)); err != nil {
		t.Fatalf("Add ads: %v", err)
	}

	m, err := set.Commit()
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return m
}

func TestPublishAndRead(t *testing.T) {
	s := newStore(t)

	m := publish(t, s, "v1", []string{"evil.example.com"}, []string{"ads.example.com"})

	if got, err := s.Current(); err != nil || got != "v1" {
		t.Fatalf("Current() = %q, %v; muốn v1", got, err)
	}
	if len(m.Lists) != 2 {
		t.Errorf("manifest có %d list, muốn 2", len(m.Lists))
	}
	if e := m.Lists["malware.txt"]; e.Entries != 1 || !strings.HasPrefix(e.ETag, "sha256:") {
		t.Errorf("mục malware.txt = %+v", e)
	}

	p, err := s.Path("malware.txt")
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("đọc file đã publish: %v", err)
	}
	if !strings.Contains(string(raw), "evil.example.com") {
		t.Errorf("file đã publish thiếu domain:\n%s", raw)
	}

	// Manifest đọc lại phải khớp bản Commit trả về.
	read, err := s.Manifest()
	if err != nil {
		t.Fatalf("Manifest: %v", err)
	}
	if read.Version != m.Version || len(read.Lists) != len(m.Lists) {
		t.Errorf("manifest đọc lại = %+v, muốn khớp %+v", read, m)
	}
}

func TestNoCurrentBeforeFirstPublish(t *testing.T) {
	s := newStore(t)
	if _, err := s.Current(); !errors.Is(err, ErrNoCurrent) {
		t.Errorf("Current() = %v, muốn ErrNoCurrent", err)
	}
}

// Đây là bài test cốt lõi của xung đột E2. Một bộ dựng dở không được để lộ ra ngoài
// dù chỉ một file.
func TestAbortedSetIsInvisible(t *testing.T) {
	s := newStore(t)
	publish(t, s, "v1", []string{"evil.example.com"}, []string{"ads.example.com"})

	set, err := s.Begin("v2", testNow)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// Chỉ ghi được một file rồi hỏng — đúng tình huống E2.
	if err := set.Add("malware.txt", render.Header{Category: "malware"}, body(t, "new.example.com")); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := set.Abort(); err != nil {
		t.Fatalf("Abort: %v", err)
	}

	if got, _ := s.Current(); got != "v1" {
		t.Errorf("Current() = %q sau khi bỏ dở, muốn vẫn là v1", got)
	}

	// Nội dung cũ vẫn nguyên vẹn và nhất quán.
	p, _ := s.Path("malware.txt")
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), "new.example.com") {
		t.Error("nội dung của bộ đã bỏ dở lại lọt vào bộ đang phát hành")
	}

	// Thư mục dựng dở không được để lại rác nhìn thấy được.
	versions, _ := s.Versions()
	for _, v := range versions {
		if v == "v2" {
			t.Error("bộ đã bỏ dở vẫn xuất hiện trong Versions()")
		}
	}
}

// Mô phỏng tiến trình chết SAU khi thư mục version đã vào vị trí nhưng TRƯỚC khi con
// trỏ current được đổi. Bộ mới tồn tại trên đĩa nhưng chưa ai trỏ tới — vô hại.
func TestCrashBeforePointerSwapLeavesCurrentIntact(t *testing.T) {
	s := newStore(t)
	publish(t, s, "v1", []string{"evil.example.com"}, []string{"ads.example.com"})

	// Tạo thủ công một thư mục version hoàn chỉnh mà không đụng tới con trỏ.
	orphan := filepath.Join(s.Root(), "v2")
	if err := os.MkdirAll(orphan, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(orphan, manifestName), []byte(`{"version":"v2"}`), 0o644); err != nil {
		t.Fatalf("ghi manifest: %v", err)
	}

	if got, _ := s.Current(); got != "v1" {
		t.Errorf("Current() = %q, muốn v1: thư mục mồ côi không được tự lên sóng", got)
	}
}

// Rollback chỉ là ghi lại con trỏ, không dựng lại gì.
func TestRollback(t *testing.T) {
	s := newStore(t)
	publish(t, s, "v1", []string{"old.example.com"}, []string{"ads.example.com"})
	publish(t, s, "v2", []string{"new.example.com"}, []string{"ads.example.com"})

	if got, _ := s.Current(); got != "v2" {
		t.Fatalf("Current() = %q, muốn v2", got)
	}

	if err := s.Rollback("v1"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if got, _ := s.Current(); got != "v1" {
		t.Errorf("Current() = %q sau rollback, muốn v1", got)
	}

	p, _ := s.Path("malware.txt")
	raw, _ := os.ReadFile(p)
	if !strings.Contains(string(raw), "old.example.com") {
		t.Errorf("sau rollback vẫn phục vụ nội dung mới:\n%s", raw)
	}
}

func TestRollbackRejectsUnknownAndIncompleteSets(t *testing.T) {
	s := newStore(t)
	publish(t, s, "v1", []string{"evil.example.com"}, []string{"ads.example.com"})

	if err := s.Rollback("không-tồn-tại"); err == nil {
		t.Error("Rollback vào version không tồn tại thành công, muốn lỗi")
	}

	// Thư mục có nhưng thiếu manifest = bộ dở dang. Không được rollback vào đó.
	partial := filepath.Join(s.Root(), "v0-partial")
	if err := os.MkdirAll(partial, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := s.Rollback("v0-partial"); err == nil {
		t.Error("Rollback vào bộ thiếu manifest thành công, muốn lỗi")
	}
}

func TestPruneKeepsRecentAndCurrent(t *testing.T) {
	s := newStore(t) // keep = 3

	for _, v := range []string{"v1", "v2", "v3", "v4", "v5"} {
		publish(t, s, v, []string{"evil.example.com"}, []string{"ads.example.com"})
	}

	// Rollback về bộ cũ nhất: Prune phải giữ nó lại dù nó nằm ngoài 3 bộ mới nhất.
	if err := s.Rollback("v1"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	removed, err := s.Prune()
	if err != nil {
		t.Fatalf("Prune: %v", err)
	}

	left, _ := s.Versions()
	has := func(v string) bool {
		for _, x := range left {
			if x == v {
				return true
			}
		}
		return false
	}

	if !has("v1") {
		t.Errorf("Prune xóa mất bộ đang phát hành; đã xóa %v, còn %v", removed, left)
	}
	for _, v := range []string{"v3", "v4", "v5"} {
		if !has(v) {
			t.Errorf("Prune xóa mất %s dù nó nằm trong %d bộ mới nhất", v, s.keep)
		}
	}
	if has("v2") {
		t.Errorf("Prune giữ lại v2 dù nó vừa ngoài ngưỡng vừa không phải bộ hiện hành")
	}
}

func TestBeginRejectsBadVersion(t *testing.T) {
	s := newStore(t)
	for _, v := range []string{"", "a/b", `a\b`} {
		if _, err := s.Begin(v, testNow); err == nil {
			t.Errorf("Begin(%q) thành công, muốn lỗi", v)
		}
	}
}

func TestCommitRejectsEmptySet(t *testing.T) {
	s := newStore(t)
	set, err := s.Begin("v1", testNow)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := set.Commit(); err == nil {
		t.Error("Commit bộ rỗng thành công, muốn lỗi")
	}
	if _, err := s.Current(); !errors.Is(err, ErrNoCurrent) {
		t.Error("bộ rỗng vẫn đổi được con trỏ current")
	}
}

func TestNewVersion(t *testing.T) {
	got := NewVersion(testNow, "sha256:abc123def456")
	want := "2026-09-07T03-00-00Z-abc123de"
	if got != want {
		t.Errorf("NewVersion() = %q, muốn %q", got, want)
	}

	// Cùng thời điểm nhưng nội dung khác thì version phải khác, nếu không hai bộ khác
	// nhau sẽ tranh nhau một thư mục.
	if NewVersion(testNow, "sha256:aaaaaaaa") == NewVersion(testNow, "sha256:bbbbbbbb") {
		t.Error("hai nội dung khác nhau cho ra cùng một version")
	}
}
