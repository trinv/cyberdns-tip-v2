// Command sync-consumer nghe OpenCTI Live Stream và ghi kết quả xuống L1.
//
// Đây là chiều OpenCTI -> PostgreSQL: analyst thu hồi một indicator trong OpenCTI thì
// domain tương ứng rời khỏi blocklist ở lượt policy kế tiếp. Không có service này,
// OpenCTI chạy nhưng đứng một mình và lời hứa "dựa trên tri thức tình báo" chỉ là hình
// thức.
//
// Chiều ngược lại (đẩy dữ liệu canonical vào OpenCTI) nằm ở connector riêng.
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/config"
	"github.com/vnnic/cyberdns-tip/internal/opencti"
	"github.com/vnnic/cyberdns-tip/internal/store"
	"github.com/vnnic/cyberdns-tip/internal/syncconsumer"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "sync-consumer")
	if err != nil {
		log.Fatalf("khởi động sync-consumer: %v", err)
	}
	defer svc.Close()

	db := store.New(svc.Pool)
	cfg := svc.Cfg.OpenCTI

	runCtx, stop := context.WithCancel(ctx)
	defer stop()

	// Chạy nền và KHÔNG làm service chết khi cấu hình chưa đủ.
	//
	// OpenCTI là thành phần tùy chọn. Thoát vì thiếu token sẽ khiến container quay vòng
	// khởi động lại mãi và làm nhiễu mọi dashboard, trong khi phần còn lại của hệ vẫn
	// đang chạy hoàn toàn bình thường.
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := run(runCtx, svc, db, cfg); err != nil {
			svc.Log.Error("sync-consumer dừng", "err", err)
		}
	}()

	if err := svc.RunServers(ctx, svc.Ready(), nil); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
	stop()

	// Chờ consumer ghi nốt checkpoint trước khi Close đóng pool.
	//
	// Không chờ thì SIGTERM sẽ đóng kết nối CSDL ngay giữa lúc consumer đang ghi, và
	// mỗi lần khởi động lại có kế hoạch — nâng cấp, dựng lại container — đều xử lý lại
	// một đoạn sự kiện. Vô hại vì đường ghi idempotent, nhưng vô ích và che mất chỉ số
	// độ trễ thật.
	select {
	case <-done:
	case <-time.After(shutdownGrace):
		svc.Log.Warn("consumer chưa dừng hẳn, thoát luôn", "grace", shutdownGrace)
	}
}

// shutdownGrace là thời gian chờ consumer ghi nốt checkpoint khi dừng.
const shutdownGrace = 10 * time.Second

func run(ctx context.Context, svc *app.Service, db *store.Store, cfg config.OpenCTI) error {
	if cfg.URL == "" || cfg.Token == "" {
		svc.Log.Warn("OpenCTI chưa cấu hình, sync-consumer đứng yên",
			"hint", "đặt opencti.url và biến môi trường TIP_OPENCTI_TOKEN")
		<-ctx.Done()
		return nil
	}

	src, err := findSource(ctx, db, cfg.SourceName)
	if err != nil {
		// Nguồn tắt là lựa chọn có chủ đích của người vận hành (migration seed nó ở
		// trạng thái tắt chờ duyệt license), không phải sự cố.
		svc.Log.Warn("chưa bật nguồn OpenCTI, sync-consumer đứng yên",
			"source", cfg.SourceName, "err", err)
		<-ctx.Done()
		return nil
	}
	if src.Origin != "opencti" {
		return fmt.Errorf("nguồn %q có origin=%q, phải là 'opencti': "+
			"origin khác sẽ khiến dữ liệu quay về từ OpenCTI bị tính là xác nhận độc lập",
			src.Name, src.Origin)
	}

	labels, err := resolveLabels(ctx, db, cfg.LabelCategories)
	if err != nil {
		return err
	}

	streamCfg, err := streamConfig(cfg)
	if err != nil {
		return err
	}

	c := syncconsumer.New(db, syncconsumer.Options{
		Source:          src,
		StreamID:        cfg.StreamID,
		LabelCategories: labels,
		CheckpointEvery: cfg.CheckpointEvery,
		CheckpointAfter: cfg.CheckpointAfter,
		Log:             svc.Log,
		Metrics:         svc.Metrics,
	})

	// Nối lại từ chỗ đã dừng.
	state, err := db.StreamState(ctx, src.ID, cfg.StreamID)
	if err != nil {
		return err
	}
	if state.Found {
		streamCfg.StartFrom = state.LastEventID

		// Ngừng quá lâu thì id sự kiện đã rơi khỏi cửa sổ lưu của stream. Dùng lại nó
		// sẽ im lặng bắt đầu từ hiện tại và bỏ trống đúng khoảng consumer đã chết —
		// mất dữ liệu mà không có triệu chứng nào. Phát lại theo mốc thời gian thay thế.
		if state.LastEventAt != nil && time.Since(*state.LastEventAt) > cfg.MaxCatchUp {
			svc.Log.Warn("khoảng ngừng vượt cửa sổ stream, phát lại theo mốc thời gian",
				"last_event_at", state.LastEventAt, "max_catch_up", cfg.MaxCatchUp)
			streamCfg.StartFrom = ""
			streamCfg.Recover = state.LastEventAt
		}
	}

	svc.Log.Info("bắt đầu nghe OpenCTI Live Stream",
		"url", streamCfg.URL, "source", src.Name,
		"start_from", streamCfg.StartFrom, "events_seen", state.EventsSeen)

	return c.Run(ctx, syncconsumer.RunOptions{
		Stream:     streamCfg,
		MinBackoff: cfg.MinBackoff,
		MaxBackoff: cfg.MaxBackoff,
	})
}

// streamConfig dựng URL stream từ cấu hình.
func streamConfig(cfg config.OpenCTI) (opencti.StreamConfig, error) {
	base := strings.TrimSuffix(cfg.URL, "/")
	url := base + "/stream"
	if cfg.StreamID != "" {
		url += "/" + cfg.StreamID
	}

	return opencti.StreamConfig{
		URL:   url,
		Token: cfg.Token,
		// BẮT BUỘC bật: tắt nó thì việc analyst xóa một indicator không bao giờ tới
		// được đây, và domain đó bị chặn mãi mà không ai gỡ được từ OpenCTI.
		ListenDelete: true,
	}, nil
}

// findSource tìm nguồn OpenCTI đang bật theo tên.
func findSource(ctx context.Context, db *store.Store, name string) (store.Source, error) {
	srcs, err := db.EnabledSources(ctx, "opencti")
	if err != nil {
		return store.Source{}, err
	}
	for _, s := range srcs {
		if s.Name == name {
			return s, nil
		}
	}
	return store.Source{}, fmt.Errorf("không có nguồn opencti đang bật tên %q", name)
}

// resolveLabels dịch cấu hình dạng tên sang id category.
//
// Tên category không tồn tại là lỗi cấu hình chứ không phải chuyện nhỏ bỏ qua được: gõ
// nhầm một tên sẽ làm cả một nhóm indicator âm thầm rơi về category mặc định, và không
// có dấu hiệu nào cho tới khi ai đó phát hiện file blocklist thiếu dữ liệu.
func resolveLabels(ctx context.Context, db *store.Store, m map[string][]string) (map[string][]int16, error) {
	if len(m) == 0 {
		return nil, nil
	}

	ids, err := db.CategoryIDsByName(ctx)
	if err != nil {
		return nil, err
	}

	out := make(map[string][]int16, len(m))
	for label, names := range m {
		var catIDs []int16
		for _, n := range names {
			id, ok := ids[n]
			if !ok {
				return nil, fmt.Errorf("opencti.label_categories: nhãn %q trỏ tới category %q không tồn tại",
					label, n)
			}
			catIDs = append(catIDs, id)
		}
		out[strings.ToLower(strings.TrimSpace(label))] = catIDs
	}
	return out, nil
}
