package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

const minimal = `
service: feed-ingestor
database:
  dsn: postgres://localhost/tip
`

func TestParseAppliesDefaults(t *testing.T) {
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if c.Env != "dev" {
		t.Errorf("Env = %q, muốn %q", c.Env, "dev")
	}
	if c.LogLevel != "info" {
		t.Errorf("LogLevel = %q, muốn %q", c.LogLevel, "info")
	}
	if c.Database.MaxConns != 8 {
		t.Errorf("MaxConns = %d, muốn 8", c.Database.MaxConns)
	}
	if c.Database.ConnectTimeout != 10*time.Second {
		t.Errorf("ConnectTimeout = %v, muốn 10s", c.Database.ConnectTimeout)
	}
	if c.Ops.Addr != "127.0.0.1:9090" {
		t.Errorf("Ops.Addr = %q, muốn cổng nội bộ mặc định", c.Ops.Addr)
	}
	// Rollback cần ít nhất một bộ cũ còn trên đĩa.
	if c.Snapshot.Keep < 1 {
		t.Errorf("Snapshot.Keep = %d, muốn >= 1", c.Snapshot.Keep)
	}
}

func TestParseRejectsUnknownField(t *testing.T) {
	// Gõ nhầm tên tùy chọn phải hỏng ngay, không được im lặng bỏ qua.
	_, err := Parse([]byte(minimal + "log_levle: debug\n"))
	if err == nil {
		t.Fatal("Parse chấp nhận khóa lạ, muốn lỗi")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want string
	}{
		{"thiếu service", "database:\n  dsn: x\n", "service"},
		{"thiếu dsn", "service: x\n", "database.dsn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse([]byte(tt.yaml))
			if err == nil {
				t.Fatalf("Parse thành công, muốn lỗi về %q", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("lỗi = %v, muốn nhắc tới %q", err, tt.want)
			}
		})
	}
}

func TestExpandEnv(t *testing.T) {
	t.Setenv("TIP_DSN", "postgres://real/db")
	t.Setenv("TIP_EMPTY", "")

	tests := []struct {
		name string
		in   string
		want string
	}{
		{"biến có sẵn", "dsn: ${TIP_DSN}", "dsn: postgres://real/db"},
		{"dùng mặc định", "env: ${TIP_ABSENT:-staging}", "env: staging"},
		{"biến rỗng thắng mặc định", "x: ${TIP_EMPTY:-fallback}", "x: "},
		{"mặc định rỗng hợp lệ", "x: ${TIP_ABSENT:-}", "x: "},
		{"nhiều tham chiếu", "a: ${TIP_DSN} ${TIP_ABSENT:-b}", "a: postgres://real/db b"},
		{"không có tham chiếu", "plain: value", "plain: value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandEnv(tt.in)
			if err != nil {
				t.Fatalf("ExpandEnv(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("ExpandEnv(%q) = %q, muốn %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestExpandEnvMissingVarIsError(t *testing.T) {
	// Một DSN rỗng lặng lẽ sẽ biến thành sự cố khó truy ở tận lúc kết nối.
	_, err := ExpandEnv("dsn: ${TIP_DEFINITELY_NOT_SET}")
	if !errors.Is(err, ErrMissingEnv) {
		t.Fatalf("lỗi = %v, muốn ErrMissingEnv", err)
	}
	if !strings.Contains(err.Error(), "TIP_DEFINITELY_NOT_SET") {
		t.Errorf("lỗi = %v, muốn nêu tên biến còn thiếu", err)
	}
}
