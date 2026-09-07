package db

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/vnnic/cyberdns-tip/migrations"
)

func TestStripOuterTransaction(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			"gỡ cặp bao ngoài",
			"BEGIN;\nCREATE TABLE t (id INT);\nCOMMIT;\n",
			"CREATE TABLE t (id INT);",
		},
		{
			"không phân biệt hoa thường",
			"begin;\nSELECT 1;\ncommit;",
			"SELECT 1;",
		},
		{
			"không có transaction thì giữ nguyên",
			"CREATE TABLE t (id INT);",
			"CREATE TABLE t (id INT);",
		},
		{
			// Chỉ gỡ khi có đủ cặp; thiếu một vế thì để nguyên cho PostgreSQL báo lỗi
			// thay vì tự đoán ý.
			"chỉ có BEGIN thì giữ nguyên",
			"BEGIN;\nSELECT 1;",
			"BEGIN;\nSELECT 1;",
		},
		{
			// COMMIT bên trong thân hàm plpgsql không được đụng tới.
			"không đụng COMMIT ở giữa",
			"BEGIN;\nSELECT 1;\nCOMMIT;\nSELECT 2;\nCOMMIT;",
			"SELECT 1;\nCOMMIT;\nSELECT 2;",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := stripOuterTransaction(tt.in); got != tt.want {
				t.Errorf("stripOuterTransaction() = %q, muốn %q", got, tt.want)
			}
		})
	}
}

func TestUpMigrationsOrderedAndSkipsDown(t *testing.T) {
	fsys := fstest.MapFS{
		"0002_seed.up.sql":   {Data: []byte("SELECT 2;")},
		"0001_init.up.sql":   {Data: []byte("SELECT 1;")},
		"0001_init.down.sql": {Data: []byte("SELECT 0;")},
		"README.md":          {Data: []byte("bỏ qua")},
	}

	got, err := upMigrations(fsys)
	if err != nil {
		t.Fatalf("upMigrations: %v", err)
	}

	want := []string{"0001_init.up.sql", "0002_seed.up.sql"}
	if len(got) != len(want) {
		t.Fatalf("upMigrations() = %v, muốn %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("upMigrations()[%d] = %q, muốn %q", i, got[i], want[i])
		}
	}
}

func TestVersion(t *testing.T) {
	if got := version("0001_init.up.sql"); got != "0001_init" {
		t.Errorf("version() = %q, muốn %q", got, "0001_init")
	}
}

// Lược đồ nhúng phải luôn dùng được: một file .sql đặt sai chỗ hoặc bị đổi tên sẽ
// làm hỏng migration lúc khởi động chứ không phải lúc build.
func TestEmbeddedMigrationsAreUsable(t *testing.T) {
	files, err := upMigrations(migrations.FS)
	if err != nil {
		t.Fatalf("upMigrations trên FS nhúng: %v", err)
	}
	if len(files) < 2 {
		t.Fatalf("chỉ nhúng được %d migration (%v), muốn ít nhất 0001 và 0002", len(files), files)
	}

	for _, name := range files {
		body, err := migrations.FS.ReadFile(name)
		if err != nil {
			t.Fatalf("đọc %s: %v", name, err)
		}
		stripped := stripOuterTransaction(string(body))
		if strings.TrimSpace(stripped) == "" {
			t.Errorf("%s rỗng sau khi gỡ transaction", name)
		}
		if leadingBegin.MatchString(stripped) {
			t.Errorf("%s vẫn còn BEGIN sau khi gỡ", name)
		}
	}

	// Mỗi .up.sql phải có .down.sql tương ứng, nếu không thì không rollback được.
	for _, name := range files {
		down := strings.TrimSuffix(name, ".up.sql") + ".down.sql"
		if _, err := migrations.FS.ReadFile(down); err != nil {
			t.Errorf("%s thiếu file down tương ứng (%s)", name, down)
		}
	}
}
