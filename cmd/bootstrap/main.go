// Command bootstrap đưa một CSDL trắng về trạng thái chạy được, rồi thoát.
//
// Tồn tại để "docker compose up -d" là đủ. Trước đây ba việc dưới đây nằm rải trong
// deploy/lab.sh và deploy/install.sh, nên ai chạy docker compose trực tiếp sẽ có một
// stack lên đủ container mà không dùng được: lược đồ trống, không có tài khoản nào để
// đăng nhập. Sau "docker compose down -v" thì lần nào cũng vậy.
//
//  1. Chạy migration.
//  2. Tạo tài khoản quản trị đầu tiên nếu chưa có.
//  3. Bật nguồn 'opencti' nếu OpenCTI đã được cấu hình.
//
// Cả ba đều idempotent: chạy lại bao nhiêu lần cũng cho cùng kết quả, và không việc nào
// ghi đè thứ người vận hành đã đổi bằng tay.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/vnnic/cyberdns-tip/internal/app"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

func main() {
	ctx := context.Background()

	// app.Bootstrap tự xử lý -migrate: nó chạy migration rồi gọi os.Exit(0). Ở đây cần
	// làm tiếp hai việc nữa nên không dùng cờ đó, mà chạy migration tường minh bên dưới.
	svc, err := app.Bootstrap(ctx, "bootstrap")
	if err != nil {
		log.Fatalf("khởi động bootstrap: %v", err)
	}
	defer svc.Close()

	if err := run(ctx, svc); err != nil {
		svc.Log.Error("bootstrap thất bại", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, svc *app.Service) error {
	if err := svc.Migrate(ctx); err != nil {
		return err
	}

	db := store.New(svc.Pool)

	if err := ensureAdmin(ctx, svc, db); err != nil {
		return err
	}
	return ensureOpenCTISource(ctx, svc, db)
}

// ensureAdmin tạo tài khoản quản trị đầu tiên nếu chưa có.
//
// KHÔNG đụng tới tài khoản đã tồn tại. store.CreateAdmin là upsert, nên gọi vô điều
// kiện ở mỗi lần khởi động sẽ đặt lại mật khẩu mà người vận hành vừa đổi trên dashboard
// — im lặng, và chỉ lộ ra ở lần đăng nhập tiếp theo.
func ensureAdmin(ctx context.Context, svc *app.Service, db *store.Store) error {
	email := envOr("TIP_ADMIN_EMAIL", "admin@vnnic.vn")

	exists, err := db.AdminExists(ctx, email)
	if err != nil {
		return err
	}
	if exists {
		svc.Log.Info("đã có tài khoản quản trị, giữ nguyên", "email", email)
		return nil
	}

	password := os.Getenv("TIP_ADMIN_PASSWORD")
	generated := password == ""
	if generated {
		// Không có mật khẩu mặc định. Một tài khoản admin/admin trên hệ điều khiển việc
		// chặn tên miền quốc gia là chuyện không được phép tồn tại dù chỉ một phút.
		if password, err = randomPassword(); err != nil {
			return err
		}
	}

	if err := db.CreateAdmin(ctx, email, email, "owner", password); err != nil {
		return err
	}

	if generated {
		// In ra stdout chứ không vào log có cấu trúc: log thường được thu thập tập
		// trung, và mật khẩu không nên nằm trong đó.
		fmt.Printf("\n"+
			"  ĐÃ TẠO TÀI KHOẢN QUẢN TRỊ\n\n"+
			"    Email:    %s\n"+
			"    Mật khẩu: %s\n\n"+
			"  Mật khẩu này được sinh ngẫu nhiên và CHỈ hiện ở đây. Ghi lại ngay, hoặc\n"+
			"  đặt TIP_ADMIN_PASSWORD trong .env để nó ổn định qua các lần dựng lại.\n"+
			"  Đọc lại sau bằng: docker compose logs bootstrap\n\n", email, password)
	} else {
		svc.Log.Info("đã tạo tài khoản quản trị từ TIP_ADMIN_PASSWORD", "email", email)
	}
	return nil
}

// ensureOpenCTISource bật nguồn 'opencti' khi và chỉ khi OpenCTI đã được cấu hình.
//
// Migration seed nguồn này ở trạng thái TẮT vì trước P4 chưa có gì đọc nó. Bật sẵn khi
// chưa có consumer nào chạy sẽ làm dashboard báo nguồn "quá hạn" mãi mãi.
//
// Điều kiện là URL và token, không phải "OpenCTI có container đang chạy": container có
// thể lên trước khi sẵn sàng, còn cấu hình thì phản ánh đúng ý định của người vận hành.
func ensureOpenCTISource(ctx context.Context, svc *app.Service, db *store.Store) error {
	cfg := svc.Cfg.OpenCTI
	if cfg.URL == "" || cfg.Token == "" {
		svc.Log.Info("OpenCTI chưa cấu hình, giữ nguyên trạng thái nguồn")
		return nil
	}

	changed, err := db.SetSourceEnabled(ctx, cfg.SourceName, "opencti", true)
	if err != nil {
		return err
	}
	if changed {
		svc.Log.Info("đã bật nguồn OpenCTI", "source", cfg.SourceName)
	} else {
		svc.Log.Info("nguồn OpenCTI đã bật sẵn", "source", cfg.SourceName)
	}
	return nil
}

func randomPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("sinh mật khẩu: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func envOr(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
