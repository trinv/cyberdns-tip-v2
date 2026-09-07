// Package psl chặn các rule quá rộng tới mức nguy hiểm.
//
// Một dòng "com" hay "vn" lọt vào feed sẽ chặn toàn bộ một TLD. Đây không phải false
// positive — đây là sự cố diện quốc gia, và nó đã từng xảy ra với nhiều nhà cung cấp
// blocklist do lỗi build ở phía nguồn. Vì hệ này fail-closed cho import (SKILL.md), một
// feed chứa rule như vậy phải bị từ chối nguyên vẹn và snapshot cũ được giữ lại.
//
// Bảng public suffix đến từ golang.org/x/net/publicsuffix, biên dịch thẳng vào binary:
// không tra cứu mạng lúc chạy, nhưng đổi lại bảng chỉ mới bằng lần cập nhật dependency
// gần nhất. TLD mới xuất hiện giữa hai lần cập nhật sẽ không được nhận diện — hệ quả là
// bỏ sót cảnh báo chứ không phải chặn nhầm, nên đây là hướng lệch an toàn.
package psl

import (
	"fmt"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// Verdict là mức an toàn của một rule.
type Verdict int

const (
	// OK: rule bình thường, nằm dưới public suffix ít nhất một nhãn.
	OK Verdict = iota

	// ReviewRequired: rule đúng bằng một public suffix thuộc phần PRIVATE của PSL
	// (blogspot.com, github.io, of.vn). Chặn cả một nền tảng hosting miễn phí đôi khi
	// là chủ ý, nên không từ chối thẳng — nhưng phải có người duyệt.
	ReviewRequired

	// Rejected: rule đúng bằng một public suffix ICANN (com, vn, co.uk, com.vn).
	// Không có lý do chính đáng nào để chặn nguyên một TLD.
	Rejected
)

func (v Verdict) String() string {
	switch v {
	case OK:
		return "ok"
	case ReviewRequired:
		return "review_required"
	case Rejected:
		return "rejected"
	default:
		return fmt.Sprintf("Verdict(%d)", int(v))
	}
}

// Result là kết luận của một lần kiểm tra.
type Result struct {
	Verdict Verdict
	// Suffix là public suffix tìm được, dùng để ghi vào log và audit import.
	Suffix string
	Reason string
}

// Check phân loại mức an toàn của một domain đã chuẩn hóa.
//
// Đầu vào phải là kết quả của domainname.Canonicalize: chữ thường, A-label punycode,
// không dấu chấm cuối, không tiền tố "*.".
func Check(domain string) Result {
	suffix, icann := publicsuffix.PublicSuffix(domain)

	if domain != suffix {
		return Result{Verdict: OK, Suffix: suffix}
	}

	if icann {
		return Result{
			Verdict: Rejected,
			Suffix:  suffix,
			Reason:  fmt.Sprintf("%q là public suffix ICANN; chặn nó là chặn cả một TLD", domain),
		}
	}

	return Result{
		Verdict: ReviewRequired,
		Suffix:  suffix,
		Reason: fmt.Sprintf(
			"%q là public suffix thuộc phần private của PSL; chặn nó là chặn cả một nền tảng hosting",
			domain),
	}
}

// ErrTooBroad được trả về khi rule bị từ chối thẳng.
type ErrTooBroad struct {
	Domain string
	Suffix string
	Reason string
}

func (e *ErrTooBroad) Error() string { return e.Reason }

// Guard là dạng rút gọn của Check dùng trong đường ingest: trả lỗi khi rule bị từ chối,
// còn ReviewRequired thì cho qua (bên gọi tự quyết định có gắn cờ chờ duyệt hay không).
func Guard(domain string) error {
	r := Check(domain)
	if r.Verdict == Rejected {
		return &ErrTooBroad{Domain: domain, Suffix: r.Suffix, Reason: r.Reason}
	}
	return nil
}

// normalizeRaw chuẩn hóa tối thiểu một token thô từ feed.
//
// Cần riêng hàm này vì domainname.Canonicalize từ chối tên một nhãn ("com", "vn")
// trước cả khi tới được hàng rào PSL. Không có đường kiểm tra riêng thì dòng nguy hiểm
// nhất có thể có trong một feed lại chỉ bị tính là một dòng lỗi bình thường và lần
// import vẫn tiếp tục.
func normalizeRaw(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "||")
	s = strings.TrimSuffix(s, "^")
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	return s
}

// CheckRaw kiểm tra một token chưa qua chuẩn hóa đầy đủ.
func CheckRaw(raw string) Result {
	n := normalizeRaw(raw)
	if n == "" {
		return Result{Verdict: OK}
	}
	return Check(n)
}
