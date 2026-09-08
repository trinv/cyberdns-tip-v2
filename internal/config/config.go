// Package config nạp cấu hình dùng chung cho mọi service CyberDNS TIP.
//
// Cấu hình đến từ file YAML. Mọi giá trị đều có thể tham chiếu biến môi trường bằng
// ${VAR} hoặc ${VAR:-mặc định}. Bí mật (DSN, token) không bao giờ nằm trong file —
// chúng đi qua biến môi trường, theo yêu cầu của CLAUDE.md.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config là cấu hình chung. Mỗi service bổ sung phần riêng của nó ở package của mình.
type Config struct {
	Service  string   `yaml:"service"`
	Env      string   `yaml:"env"`
	LogLevel string   `yaml:"log_level"`
	Database Database `yaml:"database"`
	Ops      Ops      `yaml:"ops"`
	Public   Public   `yaml:"public"`
	Snapshot Snapshot `yaml:"snapshot"`
	Schedule Schedule `yaml:"schedule"`
	OpenCTI  OpenCTI  `yaml:"opencti"`
}

// OpenCTI là cấu hình của sync-consumer.
//
// Token KHÔNG bao giờ nằm trong file: nó đi qua ${TIP_OPENCTI_TOKEN}. Một token OpenCTI
// mở toàn bộ kho tri thức tình báo, kể cả phần chưa công bố.
type OpenCTI struct {
	// URL là địa chỉ gốc của OpenCTI, ví dụ http://opencti:8080.
	URL   string `yaml:"url"`
	Token string `yaml:"token"`

	// StreamID là live stream cần nghe. Rỗng nghĩa là stream mặc định của instance.
	StreamID string `yaml:"stream_id"`

	// SourceName là tên hàng trong bảng sources đại diện cho OpenCTI. Nguồn đó phải có
	// origin='opencti', nếu không phép đếm nguồn độc lập sẽ bị lạm phát (xung đột B3).
	SourceName string `yaml:"source_name"`

	// LabelCategories ánh xạ nhãn OpenCTI sang tên category.
	//
	// Đây là chỗ hiện thực phân vai đã chốt: OpenCTI quyết định nhóm CTI, hệ này chỉ
	// dịch nhãn của nó sang tên file blocklist.
	LabelCategories map[string][]string `yaml:"label_categories"`

	// CheckpointEvery và CheckpointAfter quyết định nhịp ghi checkpoint.
	CheckpointEvery int           `yaml:"checkpoint_every"`
	CheckpointAfter time.Duration `yaml:"checkpoint_after"`

	MinBackoff time.Duration `yaml:"min_backoff"`
	MaxBackoff time.Duration `yaml:"max_backoff"`

	// MaxCatchUp là khoảng ngừng tối đa còn nối lại được bằng id sự kiện. Ngừng lâu hơn
	// thì id đã rơi khỏi cửa sổ lưu của stream và phải phát lại theo mốc thời gian.
	MaxCatchUp time.Duration `yaml:"max_catch_up"`
}

// Schedule là chu kỳ chạy của vòng lặp công việc.
type Schedule struct {
	// Interval là khoảng cách giữa hai lượt chạy.
	Interval time.Duration `yaml:"interval"`
	// RunAtStart chạy ngay một lượt lúc khởi động thay vì chờ hết chu kỳ đầu.
	RunAtStart bool `yaml:"run_at_start"`
}

type Database struct {
	DSN            string        `yaml:"dsn"`
	MaxConns       int32         `yaml:"max_conns"`
	ConnectTimeout time.Duration `yaml:"connect_timeout"`
}

// Ops là cổng vận hành nội bộ. /healthz, /readyz và /metrics chỉ sống ở đây và không
// bao giờ được phơi ra tip.cyberdns.vn.
type Ops struct {
	Addr string `yaml:"addr"`
}

// Public là cổng ra Internet, đứng sau reverse proxy tại tip.cyberdns.vn.
//
// Tách hẳn khỏi Ops: /metrics và /readyz phơi cấu trúc nội bộ cùng số liệu vận hành
// nên không bao giờ được nằm chung cổng với blocklist công khai.
type Public struct {
	// Addr rỗng nghĩa là service này không phục vụ công khai.
	//
	// Trong container phải bind 0.0.0.0, không phải 127.0.0.1: bind loopback thì
	// reverse proxy ở container khác không với tới được.
	Addr string `yaml:"addr"`

	// BaseURL là URL công khai, dùng để dựng link trong manifest và dashboard.
	BaseURL string `yaml:"base_url"`

	CacheMaxAge time.Duration `yaml:"cache_max_age"`
}

type Snapshot struct {
	// Root chứa snapshots/{version}/ cùng con trỏ current (kế hoạch §4.4).
	Root string `yaml:"root"`
	// Keep là số bộ snapshot cũ giữ lại để rollback.
	Keep int `yaml:"keep"`
}

// envRef khớp ${VAR} và ${VAR:-mặc định}.
var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}`)

// ErrMissingEnv báo một biến môi trường được tham chiếu nhưng không tồn tại và cũng
// không có giá trị mặc định.
var ErrMissingEnv = errors.New("thiếu biến môi trường")

// ExpandEnv thay thế các tham chiếu ${VAR} trong s.
//
// Biến không tồn tại và không có mặc định sẽ trả về lỗi thay vì thành chuỗi rỗng:
// một DSN rỗng lặng lẽ sẽ biến thành sự cố khó truy ở tận lúc kết nối.
func ExpandEnv(s string) (string, error) {
	var missing []string

	out := envRef.ReplaceAllStringFunc(s, func(m string) string {
		g := envRef.FindStringSubmatch(m)
		name, fallback := g[1], g[2]
		if v, ok := os.LookupEnv(name); ok {
			return v
		}
		// Phân biệt "${VAR:-}" (mặc định rỗng, hợp lệ) với "${VAR}" (bắt buộc).
		if strings.Contains(m, ":-") {
			return fallback
		}
		missing = append(missing, name)
		return ""
	})

	if len(missing) > 0 {
		return "", fmt.Errorf("%w: %s", ErrMissingEnv, strings.Join(missing, ", "))
	}
	return out, nil
}

// Load đọc và phân tích file cấu hình tại path.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("đọc cấu hình %s: %w", path, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse phân tích nội dung YAML đã nạp sẵn.
func Parse(raw []byte) (*Config, error) {
	expanded, err := ExpandEnv(string(raw))
	if err != nil {
		return nil, err
	}

	var c Config
	dec := yaml.NewDecoder(strings.NewReader(expanded))
	// Khóa lạ là lỗi: gõ nhầm tên tùy chọn im lặng còn tệ hơn hỏng hẳn.
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("phân tích YAML: %w", err)
	}

	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Env == "" {
		c.Env = "dev"
	}
	if c.LogLevel == "" {
		c.LogLevel = "info"
	}
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 8
	}
	if c.Database.ConnectTimeout == 0 {
		c.Database.ConnectTimeout = 10 * time.Second
	}
	if c.Ops.Addr == "" {
		c.Ops.Addr = "127.0.0.1:9090"
	}
	if c.Schedule.Interval == 0 {
		c.Schedule.Interval = time.Hour
	}
	if c.Public.CacheMaxAge == 0 {
		c.Public.CacheMaxAge = 5 * time.Minute
	}
	if c.Snapshot.Root == "" {
		c.Snapshot.Root = "/var/lib/cyberdns-tip/snapshots"
	}
	if c.OpenCTI.SourceName == "" {
		c.OpenCTI.SourceName = "opencti"
	}
	if c.OpenCTI.CheckpointEvery == 0 {
		c.OpenCTI.CheckpointEvery = 100
	}
	if c.OpenCTI.CheckpointAfter == 0 {
		c.OpenCTI.CheckpointAfter = 10 * time.Second
	}
	if c.OpenCTI.MinBackoff == 0 {
		c.OpenCTI.MinBackoff = time.Second
	}
	if c.OpenCTI.MaxBackoff == 0 {
		c.OpenCTI.MaxBackoff = 2 * time.Minute
	}
	if c.OpenCTI.MaxCatchUp == 0 {
		// OpenCTI giữ stream trong Redis với cửa sổ hữu hạn. Ngừng lâu hơn thì id sự
		// kiện đã rơi khỏi cửa sổ và nối lại theo id sẽ im lặng bắt đầu từ hiện tại,
		// bỏ trống đúng khoảng thời gian consumer đã chết.
		c.OpenCTI.MaxCatchUp = 24 * time.Hour
	}
	if c.Snapshot.Keep == 0 {
		// Giữ ít nhất vài bộ: rollback (kế hoạch §4.4) cần bản trước còn trên đĩa.
		c.Snapshot.Keep = 5
	}
}

func (c *Config) Validate() error {
	var errs []string
	if c.Service == "" {
		errs = append(errs, "service không được rỗng")
	}
	if c.Database.DSN == "" {
		errs = append(errs, "database.dsn không được rỗng")
	}
	if c.Snapshot.Keep < 1 {
		errs = append(errs, "snapshot.keep phải >= 1 để còn bản rollback")
	}
	if len(errs) > 0 {
		return fmt.Errorf("cấu hình không hợp lệ: %s", strings.Join(errs, "; "))
	}
	return nil
}
