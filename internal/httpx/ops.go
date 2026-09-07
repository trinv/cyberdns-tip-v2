// Package httpx cung cấp cổng vận hành nội bộ dùng chung.
package httpx

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// ReadyFunc kiểm tra service đã sẵn sàng phục vụ chưa. Trả nil nghĩa là sẵn sàng.
type ReadyFunc func(context.Context) error

// OpsServer phục vụ /healthz, /readyz và /metrics.
//
// Ba endpoint này luôn nằm trên cổng nội bộ riêng, không bao giờ chung với cổng công
// khai tip.cyberdns.vn: /metrics phơi ra cấu trúc nội bộ và số liệu vận hành.
type OpsServer struct {
	srv   *http.Server
	ready ReadyFunc
}

// NewOpsServer dựng server trên addr. ready có thể nil, khi đó service luôn sẵn sàng.
func NewOpsServer(addr string, reg *prometheus.Registry, ready ReadyFunc) *OpsServer {
	o := &OpsServer{ready: ready}
	o.srv = &http.Server{
		Addr:              addr,
		Handler:           o.handler(reg),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return o
}

func (o *OpsServer) handler(reg *prometheus.Registry) http.Handler {
	mux := http.NewServeMux()

	// Liveness: tiến trình còn sống. Không bao giờ kiểm tra phụ thuộc ngoài — nếu
	// kiểm tra, một sự cố PostgreSQL sẽ khiến orchestrator giết luôn service đang
	// phục vụ được bằng dữ liệu sẵn có.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if o.ready == nil {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok\n"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := o.ready(ctx); err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(err.Error() + "\n"))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})

	mux.Handle("GET /metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))

	return mux
}

// Handler trả về bộ định tuyến để test mà không cần mở cổng.
func (o *OpsServer) Handler() http.Handler { return o.srv.Handler }

// Start chạy server tới khi ctx bị hủy, rồi tắt êm.
func (o *OpsServer) Start(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		if err := o.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return o.srv.Shutdown(shutdownCtx)
	}
}
