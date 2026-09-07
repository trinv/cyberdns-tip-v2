// Command admin-api phục vụ REST API cho dashboard quản trị.
//
// Service này KHÔNG bao giờ được phơi thẳng ra Internet: nó cho phép đổi chính sách
// chặn tên miền. Đặt sau reverse proxy nội bộ có giới hạn IP, hoặc truy cập qua SSH
// tunnel như OpenCTI.
//
// Khởi tạo tài khoản quản trị đầu tiên:
//
//	admin-api -config configs/admin-api.yaml -create-admin ten@vnnic.vn
//
// Lệnh này in ra một mật khẩu ngẫu nhiên rồi thoát. Không có mật khẩu mặc định: một
// tài khoản admin/admin trên hệ điều khiển việc chặn tên miền quốc gia là chuyện không
// được phép tồn tại dù chỉ một phút.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"

	"github.com/vnnic/cyberdns-tip/internal/adminapi"
	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

func main() {
	ctx := context.Background()

	// Cờ riêng của service này. app.Bootstrap tự phân tích -config và -migrate; ở đây
	// chỉ cần dò thêm -create-admin trước khi vào vòng chạy bình thường.
	createAdmin := lookupFlag("-create-admin")

	svc, err := app.Bootstrap(ctx, "admin-api")
	if err != nil {
		log.Fatalf("khởi động admin-api: %v", err)
	}
	defer svc.Close()

	db := store.New(svc.Pool)

	if createAdmin != "" {
		if err := bootstrapAdmin(ctx, db, createAdmin); err != nil {
			svc.Log.Error("tạo tài khoản quản trị", "err", err)
			os.Exit(1)
		}
		return
	}

	api := &adminapi.API{
		DB:  db,
		Log: svc.Log,
		// Cookie chỉ đặt cờ Secure khi chạy sau HTTPS. Bật ở dev sẽ khiến trình duyệt
		// bỏ cookie và không ai đăng nhập được, mà lỗi thì không hiện ra ở đâu.
		Secure: svc.Cfg.Env == "production",
	}

	if err := svc.RunServers(ctx, svc.Ready(), api.Handler()); err != nil {
		svc.Log.Error("thoát do lỗi", "err", err)
	}
}

// bootstrapAdmin tạo hoặc đặt lại mật khẩu một tài khoản quản trị.
func bootstrapAdmin(ctx context.Context, db *store.Store, email string) error {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Errorf("sinh mật khẩu: %w", err)
	}
	password := base64.RawURLEncoding.EncodeToString(buf)

	if err := db.CreateAdmin(ctx, email, email, "owner", password); err != nil {
		return err
	}

	// In ra stdout chứ không ghi vào log: log thường được thu thập tập trung, và mật
	// khẩu không nên nằm trong đó.
	fmt.Printf("\nĐã tạo tài khoản quản trị.\n\n  Email:    %s\n  Mật khẩu: %s\n\n"+
		"Đổi mật khẩu ngay sau lần đăng nhập đầu tiên.\n\n", email, password)
	return nil
}

// lookupFlag đọc một cờ dạng "-name value" hoặc "-name=value" từ os.Args.
//
// Cần tự dò vì app.Bootstrap dùng FlagSet riêng của nó và sẽ báo lỗi với cờ lạ.
func lookupFlag(name string) string {
	for i, arg := range os.Args {
		if arg == name && i+1 < len(os.Args) {
			value := os.Args[i+1]
			os.Args = append(os.Args[:i], os.Args[i+2:]...)
			return value
		}
		if v, ok := cutPrefix(arg, name+"="); ok {
			os.Args = append(os.Args[:i], os.Args[i+1:]...)
			return v
		}
	}
	return ""
}

func cutPrefix(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):], true
	}
	return "", false
}
