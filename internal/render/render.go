// Package render chuyển tập rule đã quyết định thành nội dung file blocklist.
//
// Rút gọn cha/con diễn ra Ở ĐÂY chứ không phải trong CSDL. Lược đồ giữ đủ mọi rule kèm
// nguồn gốc của chúng vì claude_rm.md coi "example.com|exact" và "example.com|wildcard"
// là hai enforcement rule khác nhau và phải truy vết được. Nhưng file xuất ra thì không
// cần cả hai: ở mốc 10M domain, số dòng thừa do cha đã phủ con là khoản giảm dung lượng
// đáng kể chứ không chỉ là dọn dẹp cho đẹp (xung đột A2, A3).
package render

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// Format là định dạng file đích.
type Format string

const (
	// FormatDomain: một domain mỗi dòng. Blocky, Pi-hole và AdGuard Home đều nạp được.
	//
	// Ngữ nghĩa quan trọng: với các engine này, một dòng domain trần đã phủ luôn toàn
	// bộ cây con. Nghĩa là ở phía tiêu thụ, exact và wildcard cho ra cùng hành vi —
	// mô hình match_type vẫn giữ nguyên cho audit và policy, nhưng đừng kỳ vọng nó tạo
	// khác biệt trong file này.
	FormatDomain Format = "domain"

	// FormatWildcard: dạng "Wildcard Asterisk" mà HaGeZi công bố riêng cho Blocky.
	FormatWildcard Format = "wildcard"
)

// coversSubtree cho biết một dòng của định dạng này có phủ cả cây con hay không.
// Đây là thứ quyết định mức rút gọn được phép áp dụng.
func (f Format) coversSubtree() bool {
	switch f {
	case FormatDomain, FormatWildcard:
		return true
	default:
		return false
	}
}

// Valid báo định dạng có được hỗ trợ hay không.
func (f Format) Valid() bool {
	return f == FormatDomain || f == FormatWildcard
}

// Collapse bỏ các rule đã bị rule khác phủ.
//
// Khi định dạng đích phủ cả cây con, một rule tại "example.com" khiến mọi rule ở
// "*.example.com", "evil.example.com" và sâu hơn trở thành thừa. Kết quả là tập tối
// tiểu, đã sắp xếp, tất định.
//
// Hàm không sửa slice đầu vào.
func Collapse(rules []domainname.Rule, f Format) []domainname.Rule {
	if len(rules) == 0 {
		return nil
	}

	out := slices.Clone(rules)
	slices.SortFunc(out, func(a, b domainname.Rule) int {
		// Sắp theo chuỗi nhãn đảo chiều để tổ tiên luôn đứng ngay trước con cháu:
		// "com.example" < "com.example.evil". Nhờ vậy chỉ cần một lượt quét.
		if c := strings.Compare(reverseLabels(a.Domain), reverseLabels(b.Domain)); c != 0 {
			return c
		}
		// Cùng domain: wildcard đứng trước để nó phủ luôn bản exact (xung đột A2).
		return int(b.MatchType) - int(a.MatchType)
	})

	if !f.coversSubtree() {
		// Định dạng chỉ khớp đúng tên: chỉ bỏ được bản trùng lặp hệt nhau.
		return slices.Compact(out)
	}

	kept := out[:0]
	var lastKept string // dạng đảo chiều của rule giữ lại gần nhất

	for _, r := range out {
		rev := reverseLabels(r.Domain)

		// Bị phủ khi trùng đúng rule vừa giữ, hoặc khi nó là con cháu của rule đó.
		// Kiểm tra dấu chấm phân tách để "com.example" không nuốt nhầm
		// "com.exampleother".
		if lastKept != "" && (rev == lastKept || strings.HasPrefix(rev, lastKept+".")) {
			continue
		}

		kept = append(kept, r)
		lastKept = rev
	}
	return kept
}

// reverseLabels đảo thứ tự nhãn: "evil.example.com" -> "com.example.evil".
func reverseLabels(d string) string {
	labels := strings.Split(d, ".")
	slices.Reverse(labels)
	return strings.Join(labels, ".")
}

// Body là nội dung đã render cùng checksum của nó.
type Body struct {
	Bytes   []byte
	Entries int
	// Checksum băm CHỈ phần nội dung, không gồm header.
	//
	// Header chứa thời điểm dựng; nếu tính nó vào checksum thì mỗi lần chạy sẽ ra một
	// giá trị khác dù dữ liệu không đổi, phá vỡ cả yêu cầu "chỉ regenerate khi dữ liệu
	// thực sự thay đổi" lẫn tính ổn định của ETag. Đây là lý do checksum tách khỏi
	// header thay vì băm cả file.
	Checksum string
}

// Render sinh phần nội dung của một file blocklist.
func Render(rules []domainname.Rule, f Format) (Body, error) {
	if !f.Valid() {
		return Body{}, fmt.Errorf("render: định dạng không hỗ trợ %q", f)
	}

	collapsed := Collapse(rules, f)

	var sb strings.Builder
	sb.Grow(len(collapsed) * 24)
	for _, r := range collapsed {
		sb.WriteString(line(r, f))
		sb.WriteByte('\n')
	}

	body := []byte(sb.String())
	sum := sha256.Sum256(body)

	return Body{
		Bytes:    body,
		Entries:  len(collapsed),
		Checksum: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

func line(r domainname.Rule, f Format) string {
	switch f {
	case FormatWildcard:
		return "*." + r.Domain
	default:
		return r.Domain
	}
}

// Header là phần chú thích đặt đầu file.
type Header struct {
	Version     string
	GeneratedAt string
	Category    string
	Entries     int
	Checksum    string
	// Attribution là bắt buộc: hệ tái phát hành list dẫn xuất từ nhiều nguồn có điều
	// khoản license riêng.
	Attribution []string
}

// WriteTo ghi header rồi tới nội dung.
func WriteTo(w io.Writer, h Header, b Body) (int64, error) {
	bw := bufio.NewWriterSize(w, 128*1024)
	var n int64

	write := func(format string, args ...any) error {
		c, err := fmt.Fprintf(bw, format, args...)
		n += int64(c)
		return err
	}

	lines := []struct{ k, v string }{
		{"Category", h.Category},
		{"Version", h.Version},
		{"Generated", h.GeneratedAt},
		{"Entries", fmt.Sprint(h.Entries)},
		{"Checksum", h.Checksum},
	}
	for _, l := range lines {
		if l.v == "" {
			continue
		}
		if err := write("# %s: %s\n", l.k, l.v); err != nil {
			return n, err
		}
	}
	for _, a := range h.Attribution {
		if err := write("# Source: %s\n", a); err != nil {
			return n, err
		}
	}
	if err := write("#\n"); err != nil {
		return n, err
	}

	c, err := bw.Write(b.Bytes)
	n += int64(c)
	if err != nil {
		return n, err
	}
	return n, bw.Flush()
}
