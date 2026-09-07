package db_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/config"
	"github.com/vnnic/cyberdns-tip/internal/db"
	"github.com/vnnic/cyberdns-tip/migrations"
)

// dsnEnv trỏ tới một PostgreSQL dùng riêng cho test. Test trong file này sẽ bỏ qua khi
// biến chưa đặt, nên `go test ./...` vẫn chạy được trên máy không có PostgreSQL.
const dsnEnv = "TIP_TEST_DATABASE_DSN"

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv(dsnEnv)
	if dsn == "" {
		t.Skipf("bỏ qua: %s chưa đặt", dsnEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Open(ctx, config.Database{
		DSN:            dsn,
		MaxConns:       4,
		ConnectTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("mở CSDL test: %v", err)
	}
	t.Cleanup(pool.Close)

	// Mỗi test bắt đầu từ lược đồ trắng.
	if _, err := pool.Exec(ctx, "DROP SCHEMA public CASCADE; CREATE SCHEMA public"); err != nil {
		t.Fatalf("dọn lược đồ: %v", err)
	}
	return pool
}

func TestMigrateIsRepeatable(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)

	first, err := db.Migrate(ctx, pool, migrations.FS)
	if err != nil {
		t.Fatalf("lần migrate đầu: %v", err)
	}
	if len(first) < 2 {
		t.Fatalf("lần đầu áp dụng %d migration (%v), muốn ít nhất 2", len(first), first)
	}

	// "migrations are repeatable" — tiêu chí nghiệm thu P0 của PLAN.md.
	second, err := db.Migrate(ctx, pool, migrations.FS)
	if err != nil {
		t.Fatalf("lần migrate thứ hai: %v", err)
	}
	if len(second) != 0 {
		t.Errorf("lần hai áp dụng lại %v, muốn không áp dụng gì", second)
	}
}

func TestSchemaShape(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Mỗi tầng L0-L3 phải hiện diện; thiếu một bảng nghĩa là mô hình suy dẫn bị hụt.
	for _, table := range []string{
		"domain_evidence",                                       // L0
		"domains", "domain_sources", "domain_source_categories", // L1
		"policy_runs", "domain_decisions", "decision_changes", // L2
		"snapshot_sets", "snapshots", // L3
		"tenants", "tenant_allowlist", "tenant_denylist",
		"global_allowlist", "false_positive_events",
	} {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)",
			table).Scan(&exists)
		if err != nil {
			t.Fatalf("kiểm tra bảng %s: %v", table, err)
		}
		if !exists {
			t.Errorf("thiếu bảng %s", table)
		}
	}
}

// L0 là nền của toàn bộ khả năng dựng lại. Nếu sửa được nó thì mọi bảo đảm ở tầng trên
// đều vô nghĩa, nên bất biến này được chặn ở CSDL chứ không chỉ bằng quy ước.
func TestEvidenceIsAppendOnly(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var sourceID int64
	err := pool.QueryRow(ctx, `
		INSERT INTO sources (name, source_type) VALUES ('test-feed', 'plain')
		RETURNING id`).Scan(&sourceID)
	if err != nil {
		t.Fatalf("tạo source: %v", err)
	}

	if _, err := pool.Exec(ctx, `
		INSERT INTO domain_evidence (source_id, raw_line, raw_hash)
		VALUES ($1, '0.0.0.0 evil.example.com', 'sha256:abc')`, sourceID); err != nil {
		t.Fatalf("chèn evidence: %v", err)
	}

	for _, tc := range []struct{ name, sql string }{
		{"UPDATE", "UPDATE domain_evidence SET raw_line = 'sửa trộm'"},
		{"DELETE", "DELETE FROM domain_evidence"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, tc.sql)
			if err == nil {
				t.Fatalf("%s trên domain_evidence thành công, muốn bị từ chối", tc.name)
			}
			if !strings.Contains(err.Error(), "append-only") {
				t.Errorf("lỗi = %v, muốn nhắc tới append-only", err)
			}
		})
	}
}

// Tenant mặc định là tenant phục vụ các URL phẳng trong claude_rm.md. Hai tenant cùng
// nhận mặc định sẽ khiến /blocklist/malware.txt trở nên mơ hồ.
func TestOnlyOneDefaultTenant(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	var count int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM tenants WHERE is_default").Scan(&count); err != nil {
		t.Fatalf("đếm tenant mặc định: %v", err)
	}
	if count != 1 {
		t.Fatalf("có %d tenant mặc định sau seed, muốn đúng 1", count)
	}

	_, err := pool.Exec(ctx,
		"INSERT INTO tenants (name, slug, is_default) VALUES ('Thứ hai', 'second', TRUE)")
	if err == nil {
		t.Fatal("chèn được tenant mặc định thứ hai, muốn bị từ chối")
	}
}

// match_type chỉ nhận exact và wildcard. Regex nằm ở regex_rules: giữ regex trong
// normalized_domain mâu thuẫn với quy tắc chuẩn hóa hostname.
func TestDomainsRejectRegexMatchType(t *testing.T) {
	ctx := context.Background()
	pool := testPool(t)
	if _, err := db.Migrate(ctx, pool, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	_, err := pool.Exec(ctx,
		"INSERT INTO domains (normalized_domain, match_type) VALUES ('example.com', 2)")
	if err == nil {
		t.Fatal("chèn được match_type=2 vào domains, muốn bị từ chối")
	}

	// Nhưng exact và wildcard cùng một domain là hai rule hợp lệ, khác nhau
	// (claude_rm.md §Yêu cầu chống duplicate).
	for _, mt := range []int{0, 1} {
		if _, err := pool.Exec(ctx,
			"INSERT INTO domains (normalized_domain, match_type) VALUES ('example.com', $1)",
			mt); err != nil {
			t.Errorf("chèn match_type=%d thất bại: %v", mt, err)
		}
	}

	var n int
	if err := pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM domains WHERE normalized_domain = 'example.com'").Scan(&n); err != nil {
		t.Fatalf("đếm: %v", err)
	}
	if n != 2 {
		t.Errorf("có %d hàng cho example.com, muốn 2 (exact + wildcard)", n)
	}
}
