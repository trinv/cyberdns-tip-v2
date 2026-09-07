package blocklistsrv

import (
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/render"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
)

var testNow = time.Date(2026, 9, 7, 3, 0, 0, 0, time.UTC)

// newServer dựng một store đã publish sẵn một bộ, kèm server đọc từ đó.
func newServer(t *testing.T, malware []string) (*Server, *snapshot.Store) {
	t.Helper()

	store, err := snapshot.NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	rules := make([]domainname.Rule, len(malware))
	for i, d := range malware {
		rules[i] = domainname.Rule{Domain: d, MatchType: domainname.Exact}
	}
	body, err := render.Render(rules, render.FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	set, err := store.Begin("v1", testNow)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if err := set.Add("malware.txt", render.Header{}, body); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := set.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	return New(Options{
		Store:   store,
		Metrics: metrics.New("test", "v0"),
	}), store
}

func do(t *testing.T, h http.Handler, method, path string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestServeBlocklist(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com", "bad.example.net"})
	h := s.Handler()

	rec := do(t, h, "GET", "/blocklist/malware.txt", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mã = %d, muốn 200", rec.Code)
	}

	if ct := rec.Header().Get("Content-Type"); ct != "text/plain; charset=utf-8" {
		t.Errorf("Content-Type = %q", ct)
	}
	if rec.Header().Get("ETag") == "" {
		t.Error("thiếu ETag")
	}
	if rec.Header().Get("Last-Modified") == "" {
		t.Error("thiếu Last-Modified")
	}
	if v := rec.Header().Get("Vary"); v != "Accept-Encoding" {
		t.Errorf("Vary = %q, muốn Accept-Encoding", v)
	}

	body := rec.Body.String()
	for _, want := range []string{"evil.example.com", "bad.example.net"} {
		if !strings.Contains(body, want) {
			t.Errorf("body thiếu %q", want)
		}
	}
}

// Request có điều kiện là thứ giữ cho một file 200 MB không bị tải lại mỗi lần Blocky
// làm mới danh sách.
func TestConditionalRequestReturns304(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})
	h := s.Handler()

	first := do(t, h, "GET", "/blocklist/malware.txt", nil)
	etag := first.Header().Get("ETag")

	second := do(t, h, "GET", "/blocklist/malware.txt", map[string]string{"If-None-Match": etag})
	if second.Code != http.StatusNotModified {
		t.Errorf("mã = %d, muốn 304", second.Code)
	}
	if n := second.Body.Len(); n != 0 {
		t.Errorf("thân phản hồi 304 dài %d byte, muốn rỗng", n)
	}

	// ETag khác thì phải trả lại nội dung đầy đủ.
	third := do(t, h, "GET", "/blocklist/malware.txt", map[string]string{"If-None-Match": `"sha256:khác"`})
	if third.Code != http.StatusOK {
		t.Errorf("mã = %d với ETag khác, muốn 200", third.Code)
	}
}

func TestGzipServedFromPrebuiltFile(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com", "bad.example.net"})
	h := s.Handler()

	rec := do(t, h, "GET", "/blocklist/malware.txt", map[string]string{"Accept-Encoding": "gzip, deflate"})
	if rec.Code != http.StatusOK {
		t.Fatalf("mã = %d", rec.Code)
	}
	if enc := rec.Header().Get("Content-Encoding"); enc != "gzip" {
		t.Fatalf("Content-Encoding = %q, muốn gzip", enc)
	}

	zr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("thân phản hồi không phải gzip hợp lệ: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("giải nén: %v", err)
	}
	if !strings.Contains(string(raw), "evil.example.com") {
		t.Errorf("nội dung giải nén thiếu domain:\n%s", raw)
	}
}

// Hai biểu diễn của cùng một tài nguyên phải có ETag khác nhau, nếu không cache trung
// gian có thể trả bản nén cho client không nhận gzip.
func TestGzipAndPlainHaveDifferentETags(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})
	h := s.Handler()

	plain := do(t, h, "GET", "/blocklist/malware.txt", nil).Header().Get("ETag")
	gz := do(t, h, "GET", "/blocklist/malware.txt",
		map[string]string{"Accept-Encoding": "gzip"}).Header().Get("ETag")

	if plain == gz {
		t.Errorf("bản thường và bản nén dùng chung ETag %s", plain)
	}
}

func TestAcceptEncodingParsing(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})
	h := s.Handler()

	tests := []struct {
		header   string
		wantGzip bool
	}{
		{"gzip", true},
		{"gzip, deflate, br", true},
		{"deflate, gzip;q=1.0", true},
		{" gzip ", true},
		{"deflate", false},
		{"", false},
		// "notgzip" không được khớp nhầm thành gzip.
		{"notgzip", false},
	}

	for _, tt := range tests {
		t.Run(tt.header, func(t *testing.T) {
			rec := do(t, h, "GET", "/blocklist/malware.txt",
				map[string]string{"Accept-Encoding": tt.header})
			got := rec.Header().Get("Content-Encoding") == "gzip"
			if got != tt.wantGzip {
				t.Errorf("Accept-Encoding %q -> gzip=%v, muốn %v", tt.header, got, tt.wantGzip)
			}
		})
	}
}

func TestServeManifest(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})

	rec := do(t, s.Handler(), "GET", "/blocklist/manifest.json", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("mã = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q", ct)
	}

	var m snapshot.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("manifest không phải JSON hợp lệ: %v", err)
	}
	if m.Version != "v1" {
		t.Errorf("version = %q, muốn v1", m.Version)
	}
	if e := m.Lists["malware.txt"]; e.Entries != 1 {
		t.Errorf("mục malware.txt = %+v", e)
	}
}

// Tên file đến từ client, nên phải chặn chặt. Chuỗi nào lọt qua đây là chuỗi đi thẳng
// vào một đường dẫn hệ thống file.
func TestRejectsUnsafeNames(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})
	h := s.Handler()

	for _, path := range []string{
		"/blocklist/..%2fcurrent",
		"/blocklist/malware.txt.gz", // bản nén chỉ được lấy qua Accept-Encoding
		"/blocklist/MALWARE.TXT",
		"/blocklist/malware",
		"/blocklist/.hidden.txt",
		"/blocklist/không-tồn-tại.txt",
	} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, h, "GET", path, nil)
			if rec.Code != http.StatusNotFound {
				t.Errorf("mã = %d, muốn 404", rec.Code)
			}
		})
	}
}

// "../" được ServeMux chuẩn hóa thành redirect chứ không phải 404. Chỉ khẳng định
// "không phải 200" thì quá yếu, nên ở đây đi theo redirect để chứng minh trạng thái
// cuối thật sự không lấy được file nào.
func TestTraversalRedirectLandsNowhere(t *testing.T) {
	s, _ := newServer(t, []string{"evil.example.com"})
	h := s.Handler()

	rec := do(t, h, "GET", "/blocklist/../current", nil)
	if rec.Code == http.StatusOK {
		t.Fatalf("đường dẫn traversal trả 200:\n%s", rec.Body.String())
	}

	loc := rec.Header().Get("Location")
	if loc == "" {
		if rec.Code != http.StatusNotFound {
			t.Errorf("mã = %d, muốn 404 hoặc redirect", rec.Code)
		}
		return
	}
	if strings.HasPrefix(loc, "/blocklist/") {
		t.Fatalf("redirect vẫn nằm trong /blocklist/: %q", loc)
	}

	final := do(t, h, "GET", loc, nil)
	if final.Code != http.StatusNotFound {
		t.Errorf("đích redirect %q trả mã %d, muốn 404", loc, final.Code)
	}
	if strings.Contains(final.Body.String(), "evil.example.com") {
		t.Errorf("đích redirect lộ nội dung snapshot: %s", final.Body.String())
	}
}

// Chưa có snapshot nào không phải lỗi vĩnh viễn: client nên thử lại.
func TestNoSnapshotYieldsServiceUnavailable(t *testing.T) {
	store, err := snapshot.NewStore(t.TempDir(), 3)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	s := New(Options{Store: store, Metrics: metrics.New("test", "v0")})

	for _, path := range []string{"/blocklist/malware.txt", "/blocklist/manifest.json"} {
		rec := do(t, s.Handler(), "GET", path, nil)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: mã = %d, muốn 503", path, rec.Code)
		}
		// Không được lộ đường dẫn hệ thống file ra ngoài.
		if strings.Contains(rec.Body.String(), store.Root()) {
			t.Errorf("%s: phản hồi lộ đường dẫn nội bộ: %s", path, rec.Body.String())
		}
	}
}

// Rollback phải có hiệu lực ngay với request kế tiếp: server đọc con trỏ current mỗi
// lần phục vụ chứ không nhớ đệm.
func TestRollbackTakesEffectImmediately(t *testing.T) {
	s, store := newServer(t, []string{"old.example.com"})
	h := s.Handler()

	// Publish bộ thứ hai.
	body, _ := render.Render(
		[]domainname.Rule{{Domain: "new.example.com", MatchType: domainname.Exact}},
		render.FormatDomain)
	set, _ := store.Begin("v2", testNow.Add(time.Hour))
	_ = set.Add("malware.txt", render.Header{}, body)
	if _, err := set.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	if got := do(t, h, "GET", "/blocklist/malware.txt", nil).Body.String(); !strings.Contains(got, "new.example.com") {
		t.Fatalf("sau publish vẫn phục vụ nội dung cũ:\n%s", got)
	}

	if err := store.Rollback("v1"); err != nil {
		t.Fatalf("Rollback: %v", err)
	}

	got := do(t, h, "GET", "/blocklist/malware.txt", nil).Body.String()
	if !strings.Contains(got, "old.example.com") {
		t.Errorf("sau rollback vẫn phục vụ nội dung mới:\n%s", got)
	}
}
