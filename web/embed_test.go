package web

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestServesStaticAssets(t *testing.T) {
	tests := []struct {
		path       string
		wantType   string
		wantInBody string
	}{
		{"/app.css", "text/css", "--bg-body"},
		{"/app.js", "javascript", "api("},
		{"/index.html", "text/html", "CyberDNS TIP"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := get(t, tt.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("mã = %d, muốn 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, tt.wantType) {
				t.Errorf("Content-Type = %q, muốn chứa %q", ct, tt.wantType)
			}
			if !strings.Contains(rec.Body.String(), tt.wantInBody) {
				t.Errorf("thân phản hồi thiếu %q", tt.wantInBody)
			}
		})
	}
}

// Giao diện định tuyến bằng hash ở phía client, nên tải lại trang ở bất kỳ màn hình nào
// cũng phải ra được vỏ ứng dụng chứ không phải 404.
func TestUnknownPathsFallBackToIndex(t *testing.T) {
	for _, path := range []string{"/", "/sources", "/lookup", "/khong-ton-tai"} {
		t.Run(path, func(t *testing.T) {
			rec := get(t, path)
			if rec.Code != http.StatusOK {
				t.Fatalf("mã = %d, muốn 200", rec.Code)
			}
			if !strings.Contains(rec.Body.String(), "CyberDNS TIP") {
				t.Error("không trả về vỏ ứng dụng")
			}
		})
	}
}

// Bảng quản trị hiển thị trạng thái vận hành hiện tại; một bản cũ trong cache có thể
// khiến người vận hành ra quyết định sai.
func TestShellIsNotCached(t *testing.T) {
	rec := get(t, "/")
	if cc := rec.Header().Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Errorf("Cache-Control = %q, muốn no-store", cc)
	}
}

func TestSecurityHeaders(t *testing.T) {
	rec := get(t, "/")

	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q", got)
	}

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP thiếu %q: %s", want, csp)
		}
	}
}

// Giao diện không được nhúng tài nguyên từ bên ngoài: bảng điều khiển nội bộ mà tải
// script hay font từ CDN thì mỗi sự cố của CDN đó thành sự cố của mình, và mỗi lần tải
// là một lần rò rỉ thông tin về việc ai đang dùng hệ.
//
// Chỉ soi các dạng THỰC SỰ tải tài nguyên. "http://www.w3.org/2000/svg" trong app.js
// là định danh namespace XML, không phải một lượt tải mạng.
func TestNoExternalResourceLoads(t *testing.T) {
	patterns := []string{
		`src="http`, `src='http`, `src="//`,
		`href="http`, `href='http`, `href="//`,
		"url(http", "url(//",
		`fetch("http`, `fetch('http`,
		"@import url(http",
	}

	for _, path := range []string{"/index.html", "/app.css", "/app.js"} {
		body := get(t, path).Body.String()
		for _, p := range patterns {
			if strings.Contains(body, p) {
				t.Errorf("%s tải tài nguyên ngoài (%q)", path, p)
			}
		}
	}
}

// ETag phải là hash NỘI DUNG, không phải thời điểm build: nếu không, mỗi lần khởi động
// lại service là mọi client phải tải lại toàn bộ giao diện.
func TestETagIsContentBased(t *testing.T) {
	first := get(t, "/app.css").Header().Get("ETag")
	if first == "" {
		t.Fatal("thiếu ETag")
	}
	if second := get(t, "/app.css").Header().Get("ETag"); second != first {
		t.Errorf("ETag đổi giữa hai request: %s vs %s", first, second)
	}
	if js := get(t, "/app.js").Header().Get("ETag"); js == first {
		t.Error("hai file khác nhau dùng chung ETag")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/app.css", nil)
	req.Header.Set("If-None-Match", first)
	Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified {
		t.Errorf("request có điều kiện = %d, muốn 304", rec.Code)
	}
}

// Giao diện phải PHÂN TÍCH được, không chỉ được phục vụ.
//
// Một lỗi cú pháp trong app.js khiến trình duyệt không chạy dòng nào, và vì cả hai khối
// #login và #app đều bắt đầu ở trạng thái hidden, kết quả là một TRANG TRẮNG hoàn toàn
// — không thông báo, không dấu hiệu gì. Bộ test trước chỉ khẳng định file được phục vụ
// đúng Content-Type nên hoàn toàn im lặng trước lỗi đó, và nó đã lọt ra tới người dùng.
//
// Bỏ qua khi máy không có Node; CI luôn có.
func TestJavaScriptParses(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("bỏ qua: không có node trên PATH")
	}

	dir, err := os.MkdirTemp("", "tip-web-*")
	if err != nil {
		t.Fatalf("tạo thư mục tạm: %v", err)
	}
	defer os.RemoveAll(dir)

	src, err := files.ReadFile("app.js")
	if err != nil {
		t.Fatalf("đọc app.js: %v", err)
	}
	path := filepath.Join(dir, "app.js")
	if err := os.WriteFile(path, src, 0o600); err != nil {
		t.Fatalf("ghi file tạm: %v", err)
	}

	out, err := exec.Command(node, "--check", path).CombinedOutput()
	if err != nil {
		t.Fatalf("app.js không phân tích được:\n%s", out)
	}
}

// index.html phải tham chiếu đúng những tài nguyên mà Handler thực sự phục vụ.
//
// Một đường dẫn gõ sai ở đây cũng cho ra trang trắng y hệt, và cũng im lặng như vậy.
func TestIndexReferencesServedAssets(t *testing.T) {
	html := get(t, "/index.html").Body.String()

	for _, ref := range []string{`href="/app.css"`, `src="/app.js"`} {
		if !strings.Contains(html, ref) {
			t.Errorf("index.html thiếu %s", ref)
		}
	}

	// Và những đường dẫn đó phải trả về 200 thật.
	for _, path := range []string{"/app.css", "/app.js"} {
		if rec := get(t, path); rec.Code != http.StatusOK {
			t.Errorf("%s = %d, muốn 200", path, rec.Code)
		}
	}
}
