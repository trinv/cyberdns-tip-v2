// Command policy-engine chuyển bằng chứng thành quyết định BLOCK/MONITOR/ALLOW theo (domain, category).
//
// P0 mới dựng khung: nạp cấu hình, mở CSDL, phơi cổng vận hành nội bộ.
// Vòng lặp công việc thật sẽ được bổ sung ở P1/P5.
package main

import (
	"context"
	"log"

	"github.com/vnnic/cyberdns-tip/internal/app"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "policy-engine")
	if err != nil {
		log.Fatalf("khởi động policy-engine: %v", err)
	}
	defer svc.Close()

	if err := svc.RunOps(ctx, svc.Ready()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
}
