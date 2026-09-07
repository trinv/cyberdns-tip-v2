// Command blocklist-generator dựng và phát hành snapshot blocklist theo bộ, đồng thời
// phục vụ chúng qua HTTP tại https://tip.cyberdns.vn.
//
// Việc dựng snapshot từ PostgreSQL sẽ được bổ sung ở phần còn lại của P1; phần phục vụ
// HTTP đã hoạt động và đọc trực tiếp từ thư mục snapshot.
package main

import (
	"context"
	"log"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/blocklistsrv"
	"github.com/vnnic/cyberdns-tip/internal/snapshot"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "blocklist-generator")
	if err != nil {
		log.Fatalf("khởi động blocklist-generator: %v", err)
	}
	defer svc.Close()

	store, err := snapshot.NewStore(svc.Cfg.Snapshot.Root, svc.Cfg.Snapshot.Keep)
	if err != nil {
		svc.Log.Error("mở kho snapshot", "err", err)
		return
	}

	public := blocklistsrv.New(blocklistsrv.Options{
		Store:       store,
		Metrics:     svc.Metrics,
		Log:         svc.Log,
		CacheMaxAge: svc.Cfg.Public.CacheMaxAge,
	})

	// Readiness gắn với kho snapshot chứ không gắn với PostgreSQL: service này phục vụ
	// được bằng bộ đã publish ngay cả khi control plane đang hỏng, nên báo chưa sẵn
	// sàng vì PostgreSQL không trả lời là sai.
	ready := func(context.Context) error {
		_, err := store.Current()
		return err
	}

	if err := svc.RunServers(ctx, ready, public.Handler()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
}
