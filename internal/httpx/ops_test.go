package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/metrics"
)

func newTestServer(ready ReadyFunc) *OpsServer {
	m := metrics.New("test-service", "v0-test")
	return NewOpsServer("127.0.0.1:0", m.Registry, ready)
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestHealthzIgnoresDependencies(t *testing.T) {
	// Liveness không được phụ thuộc vào PostgreSQL: nếu phụ thuộc, một sự cố DB sẽ
	// khiến orchestrator giết luôn service vẫn đang phục vụ được bằng snapshot sẵn có.
	h := newTestServer(func(context.Context) error {
		return errors.New("postgres down")
	}).Handler()

	if rec := get(t, h, "/healthz"); rec.Code != http.StatusOK {
		t.Errorf("/healthz = %d, muốn 200 kể cả khi phụ thuộc hỏng", rec.Code)
	}
}

func TestReadyz(t *testing.T) {
	tests := []struct {
		name     string
		ready    ReadyFunc
		wantCode int
		wantBody string
	}{
		{"không có kiểm tra", nil, http.StatusOK, "ok"},
		{"sẵn sàng", func(context.Context) error { return nil }, http.StatusOK, "ok"},
		{
			"chưa sẵn sàng",
			func(context.Context) error { return errors.New("snapshot store chưa gắn") },
			http.StatusServiceUnavailable,
			"snapshot store chưa gắn",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := get(t, newTestServer(tt.ready).Handler(), "/readyz")
			if rec.Code != tt.wantCode {
				t.Errorf("/readyz = %d, muốn %d", rec.Code, tt.wantCode)
			}
			if !strings.Contains(rec.Body.String(), tt.wantBody) {
				t.Errorf("body = %q, muốn chứa %q", rec.Body.String(), tt.wantBody)
			}
		})
	}
}

func TestMetricsExposesBuildInfo(t *testing.T) {
	rec := get(t, newTestServer(nil).Handler(), "/metrics")
	if rec.Code != http.StatusOK {
		t.Fatalf("/metrics = %d, muốn 200", rec.Code)
	}

	body := rec.Body.String()
	for _, want := range []string{
		`cyberdns_build_info{service="test-service",version="v0-test"} 1`,
		"cyberdns_opencti_stream_lag_seconds",
		"cyberdns_opencti_reconcile_drift",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/metrics thiếu %q", want)
		}
	}
}

func TestInitSourceMakesFeedMetricsScrapable(t *testing.T) {
	// Prometheus không xuất metric vector chưa có label value nào. Nếu bỏ qua bước
	// khởi tạo nhãn thì cảnh báo "cyberdns_feed_up == 0" sẽ im lặng đúng vào lúc
	// cần nhất: nguồn chưa từng chạy thành công lần nào.
	m := metrics.New("test-service", "v0-test")
	srv := NewOpsServer("127.0.0.1:0", m.Registry, nil)

	before := get(t, srv.Handler(), "/metrics").Body.String()
	if strings.Contains(before, "cyberdns_feed_up") {
		t.Error("cyberdns_feed_up xuất hiện trước khi có nhãn nào; giả định của test đã sai")
	}

	m.InitSource("hagezi-tif")

	after := get(t, srv.Handler(), "/metrics").Body.String()
	for _, want := range []string{
		`cyberdns_feed_up{source="hagezi-tif"} 0`,
		`cyberdns_feed_last_success_timestamp_seconds{source="hagezi-tif"} 0`,
		`cyberdns_feed_records_total{outcome="rejected",source="hagezi-tif"} 0`,
	} {
		if !strings.Contains(after, want) {
			t.Errorf("/metrics thiếu %q sau InitSource", want)
		}
	}
}
