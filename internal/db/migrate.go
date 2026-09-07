package db

import (
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// migrateLockID là khóa advisory dùng riêng cho migration: hai tiến trình cùng khởi
// động sẽ không chạy đè lên nhau.
const migrateLockID int64 = 8_263_001

const createMigrationsTable = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  version    TEXT PRIMARY KEY,
  applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

// txWrapper khớp BEGIN;/COMMIT; bao ngoài một file migration.
var (
	leadingBegin   = regexp.MustCompile(`(?is)^\s*BEGIN\s*;`)
	trailingCommit = regexp.MustCompile(`(?is)COMMIT\s*;\s*$`)
)

// stripOuterTransaction gỡ cặp BEGIN;/COMMIT; bao ngoài file migration.
//
// File migration giữ BEGIN/COMMIT để chạy trực tiếp bằng psql khi cần, nhưng runner
// tự mở transaction riêng để bản ghi version và nội dung migration cùng commit một
// lần. Không gỡ thì sẽ có transaction lồng nhau và bản ghi version có thể commit
// tách rời khỏi thay đổi lược đồ.
func stripOuterTransaction(sql string) string {
	s := strings.TrimSpace(sql)
	if !leadingBegin.MatchString(s) || !trailingCommit.MatchString(s) {
		return s
	}
	s = leadingBegin.ReplaceAllString(s, "")
	s = trailingCommit.ReplaceAllString(s, "")
	return strings.TrimSpace(s)
}

// upMigrations trả về tên các file .up.sql theo thứ tự từ vựng.
func upMigrations(fsys fs.FS) ([]string, error) {
	entries, err := fs.Glob(fsys, "*.up.sql")
	if err != nil {
		return nil, err
	}
	sort.Strings(entries)
	return entries, nil
}

// version rút mã version từ tên file: "0001_init.up.sql" -> "0001_init".
func version(name string) string {
	return strings.TrimSuffix(name, ".up.sql")
}

// Migrate áp dụng mọi migration chưa chạy, theo thứ tự, mỗi cái trong một transaction.
// Trả về danh sách version vừa áp dụng. Chạy lại khi không có gì mới là no-op.
func Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) ([]string, error) {
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("lấy kết nối: %w", err)
	}
	defer conn.Release()

	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", migrateLockID); err != nil {
		return nil, fmt.Errorf("lấy khóa migration: %w", err)
	}
	defer func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", migrateLockID)
	}()

	if _, err := conn.Exec(ctx, createMigrationsTable); err != nil {
		return nil, fmt.Errorf("tạo bảng schema_migrations: %w", err)
	}

	applied, err := appliedVersions(ctx, conn.Conn())
	if err != nil {
		return nil, err
	}

	files, err := upMigrations(fsys)
	if err != nil {
		return nil, fmt.Errorf("liệt kê migration: %w", err)
	}

	var ran []string
	for _, name := range files {
		v := version(name)
		if applied[v] {
			continue
		}

		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return ran, fmt.Errorf("đọc %s: %w", name, err)
		}

		if err := applyOne(ctx, conn.Conn(), v, string(body)); err != nil {
			return ran, fmt.Errorf("áp dụng %s: %w", name, err)
		}
		ran = append(ran, v)
	}
	return ran, nil
}

func appliedVersions(ctx context.Context, conn *pgx.Conn) (map[string]bool, error) {
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, fmt.Errorf("đọc schema_migrations: %w", err)
	}
	defer rows.Close()

	applied := map[string]bool{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyOne(ctx context.Context, conn *pgx.Conn, v, body string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()

	if _, err := tx.Exec(ctx, stripOuterTransaction(body)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", v); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
