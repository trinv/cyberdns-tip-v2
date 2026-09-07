// Command admin-api REST API cho dashboard quản trị.
//
// P0 mới dựng khung: nạp cấu hình, mở CSDL, phơi cổng vận hành nội bộ.
// Vòng lặp công việc thật sẽ được bổ sung ở P3.
package main

import (
	"context"
	"log"

	"github.com/vnnic/cyberdns-tip/internal/app"
)

func main() {
	ctx := context.Background()

	svc, err := app.Bootstrap(ctx, "admin-api")
	if err != nil {
		log.Fatalf("khởi động admin-api: %v", err)
	}
	defer svc.Close()

	if err := svc.RunOps(ctx, svc.Ready()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
}
