// Package blocklistsrv phục vụ các file blocklist đã phát hành qua HTTP.
//
// Đây là mặt công khai của hệ, chạy sau reverse proxy tại https://tip.cyberdns.vn.
// Nó CHỈ đọc từ thư mục snapshot; nó không truy vấn PostgreSQL và không biết gì về
// policy. Nhờ vậy sự cố control plane không ảnh hưởng tới việc phục vụ: bộ snapshot
// đã publish gần nhất vẫn tiếp tục được trả về.
//
// Cổng vận hành (/healthz, /readyz, /metrics) KHÔNG nằm ở đây — chúng phơi cấu trúc
// nội bộ và số liệu vận hành nên chạy trên cổng riêng không ra Internet.
package blocklistsrv

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
)

// safeName giới hạn phần tên file mà client được yêu cầu.
//
// Đây là lớp chống path traversal: chỉ chấp nhận đúng dạng "<slug>.txt", không có dấu
// chấm kép, không có dấu gạch chéo, không có gì khác.
var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}\.txt$`)

// Options cấu hình server.
type Options struct {
	Store       *snapshot.Store
	Metrics     *metrics.Metrics
	Log         *slog.Logger
	CacheMaxAge time.Duration
}

// Server phục vụ blocklist.
type Server struct {
	store       *snapshot.Store
	metrics     *metrics.Metrics
	log         *slog.Logger
	cacheMaxAge time.Duration
}

// New dựng server.
func New(opt Options) *Server {
	if opt.CacheMaxAge <= 0 {
		opt.CacheMaxAge = 5 * time.Minute
	}
	if opt.Log == nil {
		opt.Log = slog.Default()
	}
	return &Server{
		store:       opt.Store,
		metrics:     opt.Metrics,
		log:         opt.Log,
		cacheMaxAge: opt.CacheMaxAge,
	}
}

// Handler trả về bộ định tuyến công khai.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /blocklist/manifest.json", s.instrument("manifest", s.serveManifest))
	mux.Handle("GET /blocklist/{name}", s.instrument("blocklist", s.serveList))
	return mux
}

// instrument bọc handler để đếm metric theo route và mã trạng thái.
func (s *Server) instrument(route string, h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		h(rec, r)

		if s.metrics != nil {
			// 304 được đếm riêng: đó là thước đo trực tiếp xem cache có hiệu quả không.
			s.metrics.HTTPRequests.WithLabelValues(route, strconv.Itoa(rec.status)).Inc()
			s.metrics.HTTPDurationSec.WithLabelValues(route).Observe(time.Since(start).Seconds())
		}
	})
}

func (s *Server) serveManifest(w http.ResponseWriter, r *http.Request) {
	path, err := s.store.Path("manifest.json")
	if err != nil {
		s.unavailable(w, err)
		return
	}

	m, err := s.store.Manifest()
	if err != nil {
		s.unavailable(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Version của bộ đóng vai trò ETag cho manifest: manifest đổi đúng khi bộ đổi.
	w.Header().Set("ETag", strconv.Quote(m.Version))
	w.Header().Set("Cache-Control", s.cacheControl())
	s.serveFile(w, r, path)
}

func (s *Server) serveList(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !safeName.MatchString(name) {
		http.NotFound(w, r)
		return
	}

	m, err := s.store.Manifest()
	if err != nil {
		s.unavailable(w, err)
		return
	}

	entry, ok := m.Lists[name]
	if !ok {
		http.NotFound(w, r)
		return
	}

	base, err := s.store.Path(name)
	if err != nil {
		s.unavailable(w, err)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", s.cacheControl())
	// Nội dung khác nhau theo Accept-Encoding, nên cache trung gian phải biết điều đó.
	w.Header().Set("Vary", "Accept-Encoding")

	path := base
	etag := entry.ETag

	if entry.GzipBytes > 0 && acceptsGzip(r) {
		if _, err := os.Stat(base + ".gz"); err == nil {
			path = base + ".gz"
			w.Header().Set("Content-Encoding", "gzip")
			// ETag phải khác giữa hai biểu diễn của cùng một tài nguyên, nếu không
			// cache trung gian có thể trả bản nén cho client không nhận gzip.
			etag += "-gz"
		}
	}

	w.Header().Set("ETag", strconv.Quote(etag))
	s.serveFile(w, r, path)
}

// serveFile giao phần còn lại cho http.ServeContent: nó tự xử lý If-None-Match,
// If-Modified-Since và trả 304 dựa trên ETag đã đặt ở header.
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, path string) {
	f, err := os.Open(path)
	if err != nil {
		s.unavailable(w, err)
		return
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		s.unavailable(w, err)
		return
	}

	http.ServeContent(w, r, filepath.Base(path), st.ModTime(), f)
}

// unavailable trả 503 kèm log.
//
// Không trả 500: chưa có snapshot hoặc snapshot đang bị thay thế là trạng thái tạm
// thời, và client nên thử lại chứ không nên coi là hỏng vĩnh viễn.
func (s *Server) unavailable(w http.ResponseWriter, err error) {
	if errors.Is(err, snapshot.ErrNoCurrent) {
		s.log.Warn("chưa có snapshot nào được phát hành")
	} else {
		s.log.Error("không phục vụ được snapshot", "err", err)
	}
	// Không lộ đường dẫn hay lỗi hệ thống file ra ngoài.
	http.Error(w, "blocklist tạm thời chưa sẵn sàng", http.StatusServiceUnavailable)
}

func (s *Server) cacheControl() string {
	return "public, max-age=" + strconv.Itoa(int(s.cacheMaxAge.Seconds())) + ", must-revalidate"
}

func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		if enc, _, _ := strings.Cut(strings.TrimSpace(part), ";"); enc == "gzip" {
			return true
		}
	}
	return false
}

// statusRecorder ghi lại mã trạng thái để đếm metric.
type statusRecorder struct {
	http.ResponseWriter
	status  int
	written bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.written {
		s.status = code
		s.written = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	s.written = true
	return s.ResponseWriter.Write(b)
}
