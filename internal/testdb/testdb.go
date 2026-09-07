// Package testdb cấp cho mỗi package test một schema PostgreSQL riêng.
//
// `go test ./...` chạy các package SONG SONG. Nếu mọi package test cùng dùng schema
// public của một CSDL thì chúng giẫm lên nhau: package này DROP SCHEMA trong khi
// package kia đang chạy migration, và kết quả đỏ ngẫu nhiên tùy thời điểm. Lỗi kiểu đó
// rất dễ bị đổ oan cho code.
//
// Ở đây mỗi package gọi Setup với một tên schema riêng; search_path của kết nối trỏ vào
// schema đó nên toàn bộ bảng, kiểu và index đều nằm gọn bên trong.
package testdb

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/migrations"

	"github.com/vnnic/cyberdns-tip/internal/db"
)

// DSNEnv là biến môi trường trỏ tới CSDL dùng cho test tích hợp.
const DSNEnv = "TIP_TEST_DATABASE_DSN"

// safeSchema chặn tên schema lạ: nó được nối thẳng vào câu lệnh SQL.
var safeSchema = regexp.MustCompile(`^[a-z][a-z0-9_]{0,40}$`)

// Setup mở kết nối tới CSDL test trong một schema trắng mang tên schema.
//
// Bỏ qua test khi biến môi trường chưa đặt, nên `go test ./...` vẫn chạy được trên máy
// không có PostgreSQL. Schema được xóa và tạo lại ở mỗi lần gọi.
func Setup(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()

	if !safeSchema.MatchString(schema) {
		t.Fatalf("testdb: tên schema không hợp lệ %q", schema)
	}

	dsn := os.Getenv(DSNEnv)
	if dsn == "" {
		t.Skipf("bỏ qua: %s chưa đặt", DSNEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("testdb: phân tích DSN: %v", err)
	}
	cfg.MaxConns = 4
	cfg.ConnConfig.ConnectTimeout = 10 * time.Second
	// Mọi kết nối trong pool đều làm việc bên trong schema riêng của package này.
	cfg.ConnConfig.RuntimeParams["search_path"] = schema

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("testdb: mở pool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("testdb: ping: %v", err)
	}
	t.Cleanup(pool.Close)

	reset := fmt.Sprintf("DROP SCHEMA IF EXISTS %s CASCADE; CREATE SCHEMA %s", schema, schema)
	if _, err := pool.Exec(ctx, reset); err != nil {
		t.Fatalf("testdb: dựng lại schema %s: %v", schema, err)
	}

	return pool
}

// SetupMigrated làm như Setup rồi chạy toàn bộ migration.
func SetupMigrated(t *testing.T, schema string) *pgxpool.Pool {
	t.Helper()

	pool := Setup(t, schema)
	if _, err := db.Migrate(context.Background(), pool, migrations.FS); err != nil {
		t.Fatalf("testdb: migrate: %v", err)
	}
	return pool
}
