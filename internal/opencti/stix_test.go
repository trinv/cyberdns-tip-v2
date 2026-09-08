package opencti

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

func TestParsePattern(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []domainname.Rule
		wantErr error
	}{
		{
			name:    "dạng thường gặp nhất",
			pattern: "[domain-name:value = 'evil.com']",
			want:    []domainname.Rule{{Domain: "evil.com", MatchType: domainname.Exact}},
		},
		{
			name:    "không có khoảng trắng quanh dấu bằng",
			pattern: "[domain-name:value='evil.com']",
			want:    []domainname.Rule{{Domain: "evil.com", MatchType: domainname.Exact}},
		},
		{
			name:    "nhiều giá trị nối bằng OR",
			pattern: "[domain-name:value = 'a.com' OR domain-name:value = 'b.com']",
			want: []domainname.Rule{
				{Domain: "a.com", MatchType: domainname.Exact},
				{Domain: "b.com", MatchType: domainname.Exact},
			},
		},
		{
			name:    "hostname:value cũng được nhận",
			pattern: "[hostname:value = 'host.evil.com']",
			want:    []domainname.Rule{{Domain: "host.evil.com", MatchType: domainname.Exact}},
		},
		{
			name:    "chữ hoa và dấu chấm cuối quy về cùng một dạng",
			pattern: "[domain-name:value = 'EVIL.COM.']",
			want:    []domainname.Rule{{Domain: "evil.com", MatchType: domainname.Exact}},
		},
		{
			name:    "IDN chuyển sang punycode giống hệt đường feed",
			pattern: "[domain-name:value = 'tênmiền.vn']",
			want:    []domainname.Rule{{Domain: "xn--tnmin-hsa0954c.vn", MatchType: domainname.Exact}},
		},
		{
			name:    "cùng domain lặp lại chỉ cho một rule",
			pattern: "[domain-name:value = 'evil.com' OR domain-name:value = 'EVIL.com.']",
			want:    []domainname.Rule{{Domain: "evil.com", MatchType: domainname.Exact}},
		},
		{
			name:    "giá trị hỏng bị bỏ, giá trị lành vẫn dùng được",
			pattern: "[domain-name:value = 'không hợp lệ' OR domain-name:value = 'good.com']",
			want:    []domainname.Rule{{Domain: "good.com", MatchType: domainname.Exact}},
		},
		{
			name:    "pattern IPv4 không nói về tên miền",
			pattern: "[ipv4-addr:value = '198.51.100.1']",
			wantErr: ErrNoDomain,
		},
		{
			name:    "pattern file hash không nói về tên miền",
			pattern: "[file:hashes.'SHA-256' = 'aaaa']",
			wantErr: ErrNoDomain,
		},
		{
			// url:value chứa hostname nhưng KHÔNG được suy ra domain từ đó: rút host khỏi
			// URL là việc của một bộ phân tích riêng, và đoán sai sẽ chặn cả một domain
			// lành chỉ vì nó xuất hiện đâu đó trong đường dẫn.
			name:    "url:value bị từ chối thay vì đoán",
			pattern: "[url:value = 'http://evil.com/a']",
			wantErr: ErrNoDomain,
		},
		{
			name:    "pattern rỗng",
			pattern: "",
			wantErr: ErrNoDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParsePattern(tt.pattern)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("lỗi = %v, mong đợi %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("lỗi bất ngờ: %v", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("được %v, mong đợi %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("rule[%d] = %v, mong đợi %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

// obj dựng đối tượng STIX qua JSON để số học đi đúng đường mà luồng thật đi: mọi số
// trong JSON tới Go đều là float64, và ép kiểu tay sẽ giấu mất lỗi đó.
func obj(t *testing.T, raw string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("JSON mẫu hỏng: %v", err)
	}
	return m
}

func TestFromSTIXIndicator(t *testing.T) {
	rec, err := FromSTIX(obj(t, `{
		"type": "indicator",
		"id": "indicator--1111",
		"pattern": "[domain-name:value = 'evil.com']",
		"pattern_type": "stix",
		"confidence": 80,
		"labels": ["malware"],
		"modified": "2026-09-08T10:00:00.000Z",
		"valid_until": "2026-12-31T00:00:00.000Z"
	}`))
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}

	if rec.STIXID != "indicator--1111" {
		t.Errorf("STIXID = %q", rec.STIXID)
	}
	if len(rec.Rules) != 1 || rec.Rules[0].Domain != "evil.com" {
		t.Errorf("Rules = %v", rec.Rules)
	}
	if rec.Confidence != 80 {
		t.Errorf("Confidence = %d, mong đợi 80", rec.Confidence)
	}
	if rec.Revoked {
		t.Error("Revoked = true dù đối tượng không đặt trường này")
	}
	if !rec.Detection {
		t.Error("Detection phải mặc định true khi OpenCTI không nói gì")
	}
	if rec.Modified.IsZero() {
		t.Error("Modified rỗng")
	}
	if rec.ValidUntil == nil {
		t.Fatal("ValidUntil rỗng")
	}
	if rec.ValidUntil.Year() != 2026 || rec.ValidUntil.Month() != 12 {
		t.Errorf("ValidUntil = %v", rec.ValidUntil)
	}
	if len(rec.Labels) != 1 || rec.Labels[0] != "malware" {
		t.Errorf("Labels = %v", rec.Labels)
	}
}

func TestFromSTIXObservable(t *testing.T) {
	rec, err := FromSTIX(obj(t, `{
		"type": "domain-name",
		"id": "domain-name--2222",
		"value": "Bad.Example.COM."
	}`))
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if len(rec.Rules) != 1 || rec.Rules[0].Domain != "bad.example.com" {
		t.Fatalf("Rules = %v", rec.Rules)
	}
	if rec.Rules[0].MatchType != domainname.Exact {
		t.Errorf("MatchType = %v, mong đợi exact", rec.Rules[0].MatchType)
	}
}

// Trường revoked phải tới Record nguyên vẹn: nó là nấc 5 của thang ưu tiên và là thứ duy
// nhất một analyst dùng để gỡ chặn ngay một domain mà nhiều feed còn liệt kê.
func TestFromSTIXRevoked(t *testing.T) {
	rec, err := FromSTIX(obj(t, `{
		"type": "indicator",
		"id": "indicator--3333",
		"pattern": "[domain-name:value = 'falsepositive.vn']",
		"revoked": true
	}`))
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if !rec.Revoked {
		t.Error("Revoked = false dù đối tượng đặt revoked=true")
	}
}

func TestFromSTIXDetectionFalse(t *testing.T) {
	rec, err := FromSTIX(obj(t, `{
		"type": "indicator",
		"id": "indicator--4444",
		"pattern": "[domain-name:value = 'research.example']",
		"x_opencti_detection": false
	}`))
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if rec.Detection {
		t.Error("Detection = true dù OpenCTI nói rõ detection=false")
	}
}

func TestFromSTIXRejects(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr error
	}{
		{
			name:    "thiếu định danh",
			raw:     `{"type": "indicator", "pattern": "[domain-name:value = 'a.com']"}`,
			wantErr: ErrUnsupported,
		},
		{
			name:    "kiểu không xử lý được",
			raw:     `{"type": "ipv4-addr", "id": "ipv4-addr--1", "value": "198.51.100.1"}`,
			wantErr: ErrUnsupported,
		},
		{
			name:    "indicator không nói về tên miền",
			raw:     `{"type": "indicator", "id": "indicator--5", "pattern": "[ipv4-addr:value = '198.51.100.1']"}`,
			wantErr: ErrNoDomain,
		},
		{
			name:    "observable có value rỗng",
			raw:     `{"type": "domain-name", "id": "domain-name--6", "value": ""}`,
			wantErr: ErrNoDomain,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := FromSTIX(obj(t, tt.raw)); !errors.Is(err, tt.wantErr) {
				t.Fatalf("lỗi = %v, mong đợi %v", err, tt.wantErr)
			}
		})
	}
}

// Đối tượng lấy qua GraphQL (đường đối soát B7) dùng entity_type viết hoa và x_opencti_id
// thay cho type/id của luồng stream. Cùng một hàm phải hiểu cả hai dạng, nếu không job
// đối soát sẽ báo lệch toàn bộ.
func TestFromSTIXGraphQLShape(t *testing.T) {
	rec, err := FromSTIX(obj(t, `{
		"entity_type": "Indicator",
		"x_opencti_id": "9f0a",
		"pattern": "[domain-name:value = 'evil.com']"
	}`))
	if err != nil {
		t.Fatalf("lỗi bất ngờ: %v", err)
	}
	if rec.STIXID != "9f0a" {
		t.Errorf("STIXID = %q, mong đợi 9f0a", rec.STIXID)
	}
	if len(rec.Rules) != 1 {
		t.Fatalf("Rules = %v", rec.Rules)
	}
}

func TestParseSTIXTime(t *testing.T) {
	for _, s := range []string{
		"2026-09-08T10:00:00.000Z",
		"2026-09-08T10:00:00Z",
		"2026-09-08T10:00:00.123456Z",
		"2026-09-08T17:00:00+07:00",
	} {
		got := parseSTIXTime(s)
		if got == nil {
			t.Errorf("parseSTIXTime(%q) = nil", s)
			continue
		}
		if got.Location().String() != "UTC" {
			t.Errorf("parseSTIXTime(%q) không quy về UTC: %v", s, got.Location())
		}
	}

	for _, s := range []string{"", "hôm qua", "2026-09-08"} {
		if got := parseSTIXTime(s); got != nil {
			t.Errorf("parseSTIXTime(%q) = %v, mong đợi nil", s, got)
		}
	}
}
