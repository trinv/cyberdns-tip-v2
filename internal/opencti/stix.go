// Package opencti chuyển sự kiện Live Stream của OpenCTI thành bản ghi canonical.
//
// Đây là chiều OpenCTI -> PostgreSQL. Chiều ngược lại (đẩy STIX vào OpenCTI) nằm ở
// connector riêng.
//
// Toàn bộ phần phân tích ở file này là hàm thuần: cùng đầu vào luôn cho cùng đầu ra,
// không chạm mạng, không chạm CSDL. Nhờ vậy nó kiểm chứng được đầy đủ mà không cần một
// instance OpenCTI đang chạy.
package opencti

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// domainPattern rút giá trị domain-name khỏi một STIX pattern.
//
// Cố tình KHÔNG viết một bộ phân tích STIX pattern đầy đủ. Ngữ pháp đó hỗ trợ toán tử
// so sánh, phép lồng, qualifier thời gian và nhiều kiểu observable; hiện thực đủ nó là
// một dự án riêng và mọi thiếu sót đều biến thành domain bị chặn sai. Ở đây chỉ nhận
// đúng dạng bình đẳng trên domain-name:value — dạng mà OpenCTI sinh ra cho indicator
// tên miền — và từ chối mọi thứ khác một cách tường minh.
var domainPattern = regexp.MustCompile(`domain-name:value\s*=\s*'([^']+)'`)

// hostnamePattern nhận thêm dạng hostname:value mà một số nguồn dùng.
var hostnamePattern = regexp.MustCompile(`hostname:value\s*=\s*'([^']+)'`)

var (
	// ErrNoDomain: pattern hợp lệ nhưng không nói về tên miền (IP, URL, file hash...).
	ErrNoDomain = errors.New("opencti: pattern không chứa tên miền")
	// ErrUnsupported: đối tượng không phải thứ ta biết cách xử lý.
	ErrUnsupported = errors.New("opencti: kiểu đối tượng không hỗ trợ")
)

// ParsePattern rút mọi tên miền khỏi một STIX pattern.
//
// Trả về rule đã chuẩn hóa qua đúng hàm mà đường thu thập feed dùng, nên một domain đến
// từ OpenCTI và cùng domain đó đến từ feed sẽ quy về CÙNG một hàng canonical. Không
// dùng chung hàm chuẩn hóa thì hai đường sẽ sinh ra hai bản ghi cho một tên miền, và
// phép đếm nguồn độc lập lệch theo.
func ParsePattern(pattern string) ([]domainname.Rule, error) {
	if pattern == "" {
		return nil, ErrNoDomain
	}

	var raw []string
	for _, m := range domainPattern.FindAllStringSubmatch(pattern, -1) {
		raw = append(raw, m[1])
	}
	for _, m := range hostnamePattern.FindAllStringSubmatch(pattern, -1) {
		raw = append(raw, m[1])
	}
	if len(raw) == 0 {
		return nil, ErrNoDomain
	}

	seen := make(map[domainname.Rule]struct{}, len(raw))
	var out []domainname.Rule
	for _, v := range raw {
		rules, err := domainname.ParseLine(v)
		if err != nil {
			// Một giá trị hỏng không làm hỏng cả pattern: pattern có thể liệt kê nhiều
			// giá trị và những giá trị còn lại vẫn dùng được.
			continue
		}
		for _, r := range rules {
			if _, dup := seen[r]; dup {
				continue
			}
			seen[r] = struct{}{}
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, ErrNoDomain
	}
	return out, nil
}

// Record là một indicator của OpenCTI đã quy về mô hình canonical.
type Record struct {
	// STIXID là định danh dùng để đối chiếu với bản ghi đã lưu, và là thứ phải ánh xạ
	// lại khi OpenCTI gộp hai entity.
	STIXID string
	Rules  []domainname.Rule

	// Labels là nhãn OpenCTI gắn cho indicator. Chính chúng quyết định category, theo
	// đúng phân vai đã chốt: OpenCTI quyết định nhóm CTI, hệ này chỉ ánh xạ. Việc ánh
	// xạ nhãn sang category nằm ở tầng trên vì nó cần tra CSDL, còn file này thuần túy.
	Labels     []string
	Confidence int

	// Revoked là phủ định TƯỜNG MINH của analyst: nó triệt tiêu mọi nguồn khác.
	Revoked bool
	// ValidUntil là phân rã THỤ ĐỘNG: chỉ rút đóng góp của riêng OpenCTI.
	ValidUntil *time.Time

	// Modified là dấu thời gian của chính OpenCTI. Dùng để bỏ qua sự kiện cũ đến muộn,
	// vì SSE không bảo đảm thứ tự sau khi kết nối lại.
	Modified time.Time

	// Detection = false nghĩa là indicator chỉ để phân tích, không dùng để chặn.
	Detection bool
}

// stixObject là phần đối tượng STIX mà ta quan tâm.
type stixObject struct {
	Type       string   `json:"type"`
	ID         string   `json:"id"`
	Pattern    string   `json:"pattern"`
	Value      string   `json:"value"`
	Revoked    bool     `json:"revoked"`
	Confidence int      `json:"confidence"`
	Modified   string   `json:"modified"`
	ValidUntil string   `json:"valid_until"`
	Labels     []string `json:"labels"`

	// OpenCTI bổ sung các trường ngoài chuẩn STIX.
	XOpenCTIID        string `json:"x_opencti_id"`
	XOpenCTIDetection *bool  `json:"x_opencti_detection"`
	// EntityType xuất hiện ở đối tượng lấy qua API (viết hoa), không có ở luồng stream.
	EntityType string `json:"entity_type"`
}

// FromSTIX chuyển một đối tượng STIX thành Record.
//
// Nhận cả indicator (mang pattern) lẫn observable domain-name (mang value): OpenCTI
// phát cả hai loại lên stream, và chỉ nghe một loại sẽ bỏ sót phân nửa dữ liệu.
func FromSTIX(obj map[string]any) (Record, error) {
	o, err := decodeObject(obj)
	if err != nil {
		return Record{}, err
	}

	id := o.ID
	if id == "" {
		id = o.XOpenCTIID
	}
	if id == "" {
		return Record{}, fmt.Errorf("%w: thiếu định danh", ErrUnsupported)
	}

	rec := Record{
		STIXID:     id,
		Labels:     o.Labels,
		Confidence: o.Confidence,
		Revoked:    o.Revoked,
		// Mặc định TRUE: chỉ khi OpenCTI nói rõ detection=false thì mới bỏ qua. Coi
		// trường thiếu là "không dùng để chặn" sẽ khiến mọi indicator từ nguồn không
		// đặt trường này bị âm thầm bỏ hết.
		Detection: true,
	}
	if o.XOpenCTIDetection != nil {
		rec.Detection = *o.XOpenCTIDetection
	}

	if t := parseSTIXTime(o.Modified); t != nil {
		rec.Modified = *t
	}
	rec.ValidUntil = parseSTIXTime(o.ValidUntil)

	kind := strings.ToLower(o.Type)
	if kind == "" {
		kind = strings.ToLower(o.EntityType)
	}

	switch kind {
	case "indicator":
		rules, err := ParsePattern(o.Pattern)
		if err != nil {
			return Record{}, err
		}
		rec.Rules = rules

	case "domain-name", "hostname":
		rules, err := domainname.ParseLine(o.Value)
		if err != nil {
			return Record{}, fmt.Errorf("%w: %v", ErrNoDomain, err)
		}
		rec.Rules = rules

	default:
		return Record{}, fmt.Errorf("%w: %q", ErrUnsupported, kind)
	}

	return rec, nil
}

// decodeObject chuyển map rời rạc thành struct có kiểu.
//
// Đi vòng qua JSON thay vì ép kiểu từng trường: đối tượng STIX có hàng chục trường tùy
// chọn và kiểu số của chúng đến từ JSON là float64, nên ép tay là nguồn lỗi im lặng.
func decodeObject(obj map[string]any) (stixObject, error) {
	raw, err := json.Marshal(obj)
	if err != nil {
		return stixObject{}, fmt.Errorf("opencti: mã hóa lại đối tượng: %w", err)
	}
	var o stixObject
	if err := json.Unmarshal(raw, &o); err != nil {
		return stixObject{}, fmt.Errorf("opencti: giải mã đối tượng: %w", err)
	}
	return o, nil
}

// parseSTIXTime nhận các dạng dấu thời gian mà OpenCTI phát ra.
func parseSTIXTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			u := t.UTC()
			return &u
		}
	}
	return nil
}
