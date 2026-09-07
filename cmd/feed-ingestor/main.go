// Command feed-ingestor thu thập, chuẩn hóa và nạp các nguồn feed vào PostgreSQL.
//
// P0 mới dựng khung: nạp cấu hình, mở CSDL, phơi cổng vận hành nội bộ.
// Vòng lặp công việc thật sẽ được bổ sung ở P1.
package main

import (
	"context"
	"log"

	"github.com/vnnic/cyberdns-tip/internal/app"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "feed-ingestor")
	if err != nil {
		log.Fatalf("khởi động feed-ingestor: %v", err)
	}
	defer svc.Close()

	if err := svc.RunOps(ctx, svc.Ready()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
}
