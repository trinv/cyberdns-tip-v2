// Package app gom phần khởi động chung của mọi service: cờ dòng lệnh, cấu hình,
// log, metrics, kết nối CSDL và cổng vận hành.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/config"
	"github.com/vnnic/cyberdns-tip/internal/db"
	"github.com/vnnic/cyberdns-tip/internal/httpx"
	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/migrations"
)

// Version do ldflags gắn lúc build.
var Version = "dev"

// Service là bối cảnh chạy dùng chung.
type Service struct {
	Name    string
	Cfg     *config.Config
	Log     *slog.Logger
	Metrics *metrics.Metrics
	Pool    *pgxpool.Pool
}

// Bootstrap phân tích cờ dòng lệnh, nạp cấu hình và dựng mọi thứ dùng chung.
// Gọi Close khi xong.
func Bootstrap(ctx context.Context, name string) (*Service, error) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	cfgPath := fs.String("config", "configs/"+name+".yaml", "đường dẫn file cấu hình")
	migrate := fs.Bool("migrate", false, "chạy migration rồi thoát")
	if err := fs.Parse(os.Args[1:]); err != nil {
		return nil, err
	}

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return nil, err
	}

	log := newLogger(cfg.LogLevel).With("service", name, "version", Version, "env", cfg.Env)

	pool, err := db.Open(ctx, cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("kết nối PostgreSQL: %w", err)
	}

	if *migrate {
		applied, err := db.Migrate(ctx, pool, migrations.FS)
		if err != nil {
			pool.Close()
			return nil, fmt.Errorf("migration: %w", err)
		}
		log.Info("migration hoàn tất", "applied", applied, "count", len(applied))
		pool.Close()
		os.Exit(0)
	}

	return &Service{
		Name:    name,
		Cfg:     cfg,
		Log:     log,
		Metrics: metrics.New(name, Version),
		Pool:    pool,
	}, nil
}

// Migrate chạy migration trên pool đang mở.
//
// Tách khỏi cờ -migrate của Bootstrap (vốn chạy xong là os.Exit) để cmd/bootstrap còn
// làm tiếp các bước khởi tạo khác trong cùng một tiến trình.
func (s *Service) Migrate(ctx context.Context) error {
	applied, err := db.Migrate(ctx, s.Pool, migrations.FS)
	if err != nil {
		return fmt.Errorf("migration: %w", err)
	}
	s.Log.Info("migration hoàn tất", "applied", applied, "count", len(applied))
	return nil
}

func newLogger(level string) *slog.Logger {
	var lv slog.Level
	if err := lv.UnmarshalText([]byte(level)); err != nil {
		lv = slog.LevelInfo
	}
	// Log JSON có cấu trúc, theo yêu cầu của CLAUDE.md.
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv}))
}

// Close giải phóng tài nguyên dùng chung.
func (s *Service) Close() {
	if s.Pool != nil {
		s.Pool.Close()
	}
}

// Ready trả về hàm kiểm tra sẵn sàng mặc định: CSDL còn trả lời.
func (s *Service) Ready() httpx.ReadyFunc {
	return func(ctx context.Context) error {
		if err := s.Pool.Ping(ctx); err != nil {
			return fmt.Errorf("postgres không sẵn sàng: %w", err)
		}
		return nil
	}
}

// RunOps chạy cổng vận hành tới khi nhận SIGINT/SIGTERM.
//
// P0 mới chỉ dựng khung: mỗi service sẽ thay hàm này bằng vòng lặp công việc riêng ở
// các phase sau, nhưng cổng vận hành thì giữ nguyên.
func (s *Service) RunOps(ctx context.Context, ready httpx.ReadyFunc) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	ops := httpx.NewOpsServer(s.Cfg.Ops.Addr, s.Metrics.Registry, ready)
	s.Log.Info("cổng vận hành đang chạy", "addr", s.Cfg.Ops.Addr)

	if err := ops.Start(ctx); err != nil {
		return err
	}
	s.Log.Info("đã dừng")
	return nil
}

// RunServers chạy cổng vận hành nội bộ và, nếu có cấu hình, cổng công khai; dừng êm
// khi nhận SIGINT/SIGTERM.
//
// Hai cổng tách biệt là có chủ ý: /metrics và /readyz phơi cấu trúc nội bộ nên không
// bao giờ được nằm chung cổng với blocklist ra Internet.
func (s *Service) RunServers(ctx context.Context, ready httpx.ReadyFunc, public http.Handler) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 2)

	ops := httpx.NewOpsServer(s.Cfg.Ops.Addr, s.Metrics.Registry, ready)
	s.Log.Info("cổng vận hành đang chạy", "addr", s.Cfg.Ops.Addr)
	go func() { errCh <- ops.Start(ctx) }()

	if public != nil && s.Cfg.Public.Addr != "" {
		srv := &http.Server{
			Addr:              s.Cfg.Public.Addr,
			Handler:           public,
			ReadHeaderTimeout: 10 * time.Second,
			// Không đặt WriteTimeout: all.txt ở mốc 10M domain cỡ vài trăm MB và một
			// client chậm hoàn toàn có thể cần nhiều phút để tải xong.
			IdleTimeout: 120 * time.Second,
		}
		s.Log.Info("cổng công khai đang chạy",
			"addr", s.Cfg.Public.Addr, "base_url", s.Cfg.Public.BaseURL)

		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errCh <- err
				return
			}
			errCh <- nil
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_ = srv.Shutdown(shutdownCtx)
		}()
	} else {
		errCh <- nil
	}

	// Chờ CẢ HAI server rồi mới quyết định, và giữ lại lỗi đầu tiên gặp được.
	//
	// Bản trước lấy lỗi ở lần nhận thứ nhất rồi bỏ qua lần thứ hai. Khi service chỉ có
	// một server thật (feed-ingestor và policy-engine không có cổng công khai), nhánh
	// else đẩy nil vào channel ngay lập tức, nên lỗi bind cổng của ops server rơi vào
	// lần nhận thứ hai và bị nuốt mất — tiến trình thoát với mã 0 mà không log gì.
	// Một service không bind được cổng phải hỏng thật to, không phải im lặng biến mất.
	var firstErr error
	for range 2 {
		if err := <-errCh; err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return firstErr
	}

	s.Log.Info("đã dừng")
	return nil
}
