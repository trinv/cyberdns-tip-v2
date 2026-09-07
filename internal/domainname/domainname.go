// Package domainname chuyển một dòng thô từ feed thành rule canonical.
//
// Đây là hàm chuẩn hóa duy nhất của toàn hệ. Mọi nguồn đều phải đi qua đây trước khi
// chạm tới CSDL, vì cùng một domain có thể tới từ nhiều feed dưới nhiều cách viết khác
// nhau — unicode và punycode, chữ hoa, dấu chấm cuối, định dạng hosts, cú pháp Adblock.
// Chuẩn hóa không nhất quán sẽ sinh ra bản ghi trùng lặp mà không có triệu chứng nào
// nhìn thấy được: hai hàng cho cùng một domain, phép đếm nguồn độc lập bị lệch, và
// blocklist phình ra mà không ai giải thích được (xung đột A7 trong kế hoạch).
//
// Hàm ở package này thuần túy và tất định: cùng đầu vào luôn cho cùng đầu ra, không
// đọc đồng hồ, không chạm mạng.
package domainname

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"
)

// MatchType phân biệt rule khớp đúng một domain với rule khớp cả cây con.
//
// Giá trị khớp với cột match_type trong CSDL: 0 = exact, 1 = wildcard.
type MatchType uint8

const (
	Exact    MatchType = 0
	Wildcard MatchType = 1
)

func (m MatchType) String() string {
	switch m {
	case Exact:
		return "exact"
	case Wildcard:
		return "wildcard"
	default:
		return fmt.Sprintf("MatchType(%d)", uint8(m))
	}
}

// Rule là một luật đã chuẩn hóa.
//
// Domain không bao giờ chứa tiền tố "*." — ngữ nghĩa wildcard nằm ở MatchType. Nhét
// dấu sao vào chính chuỗi domain sẽ làm hỏng khóa dedup và khiến "*.example.com" với
// "example.com|wildcard" thành hai thứ khác nhau (CLAUDE.md quy tắc 5).
type Rule struct {
	Domain    string
	MatchType MatchType
}

var (
	// ErrSkip: dòng hợp lệ nhưng không chứa rule (chú thích, dòng trống).
	// Không tính vào tỉ lệ lỗi parse.
	ErrSkip = errors.New("dòng không chứa rule")

	// ErrIP: là địa chỉ IP. Bảng domains chỉ chứa hostname; IOC dạng IP cần bảng riêng
	// (docs/IMPLEMENTATION.md).
	ErrIP = errors.New("là địa chỉ IP, không phải hostname")

	// ErrInvalid: không phải hostname hợp lệ. Tính vào tỉ lệ lỗi parse.
	ErrInvalid = errors.New("không phải hostname hợp lệ")
)

// idnaProfile chuyển tên miền quốc tế hóa về A-label.
//
// StrictDomainName tắt có chủ đích: blocklist thật có nhãn chứa gạch dưới (_dmarc,
// _dnslink, _acme-challenge). Bật nó lên sẽ loại bỏ những nhãn đó một cách âm thầm.
var idnaProfile = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.StrictDomainName(false),
)

const (
	maxNameLen  = 253
	maxLabelLen = 63
)

// Canonicalize chuẩn hóa một hostname đã tách sẵn khỏi cú pháp feed.
//
// Kết quả luôn là: A-label punycode, chữ thường, không dấu chấm cuối. Nó không xử lý
// tiền tố wildcard — đó là việc của ParseLine.
func Canonicalize(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	if s == "" {
		return "", ErrInvalid
	}

	// Kiểm tra IP trước IDNA: "1.2.3.4" là chuỗi ASCII hợp lệ nên IDNA sẽ cho qua,
	// và ta sẽ lặng lẽ lưu một địa chỉ IP vào bảng hostname.
	if isIP(s) {
		return "", ErrIP
	}

	ascii, err := idnaProfile.ToASCII(s)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	ascii = strings.ToLower(ascii)

	if err := validate(ascii); err != nil {
		return "", err
	}
	return ascii, nil
}

func isIP(s string) bool {
	// Bỏ ngoặc vuông của dạng "[::1]".
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	_, err := netip.ParseAddr(s)
	return err == nil
}

func validate(name string) error {
	if len(name) > maxNameLen {
		return fmt.Errorf("%w: dài %d byte, tối đa %d", ErrInvalid, len(name), maxNameLen)
	}

	labels := strings.Split(name, ".")
	if len(labels) < 2 {
		// Tên một nhãn (localhost, một TLD trần) không phải mục tiêu chặn hợp lệ.
		// Trường hợp public suffix nguy hiểm hơn được package psl chặn riêng.
		return fmt.Errorf("%w: chỉ có một nhãn", ErrInvalid)
	}

	for _, l := range labels {
		if l == "" {
			return fmt.Errorf("%w: có nhãn rỗng", ErrInvalid)
		}
		if len(l) > maxLabelLen {
			return fmt.Errorf("%w: nhãn %q dài %d byte, tối đa %d", ErrInvalid, l, len(l), maxLabelLen)
		}
		for _, r := range l {
			if !isHostRune(r) {
				return fmt.Errorf("%w: ký tự không hợp lệ %q trong %q", ErrInvalid, r, l)
			}
		}
	}
	return nil
}

func isHostRune(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
}

// ParseLine chuyển một dòng thô từ feed thành các rule canonical.
//
// Trả về slice vì định dạng hosts cho phép nhiều hostname trên một dòng
// ("0.0.0.0 a.com b.com"). Chỉ lấy phần tử đầu sẽ âm thầm bỏ sót domain cần chặn.
//
// Các định dạng nhận được:
//
//	example.com                 exact
//	EXAMPLE.COM.                exact  (chữ thường hóa, bỏ dấu chấm cuối)
//	*.example.com               wildcard
//	.example.com                wildcard
//	0.0.0.0 example.com         exact  (hosts)
//	127.0.0.1 a.com b.com       exact  (hosts, nhiều hostname)
//	||example.com^              wildcard (Adblock: domain và mọi subdomain)
//	||example.com^$important    wildcard (bỏ qua phần modifier)
//	# chú thích                 ErrSkip
func ParseLine(line string) ([]Rule, error) {
	line = stripComment(line)
	if line == "" {
		return nil, ErrSkip
	}

	if rest, ok := strings.CutPrefix(line, "||"); ok {
		return parseAdblock(rest)
	}

	fields := strings.Fields(line)
	switch {
	case len(fields) == 0:
		return nil, ErrSkip

	case len(fields) == 1:
		r, err := parseToken(fields[0])
		if err != nil {
			return nil, err
		}
		return []Rule{r}, nil

	case isIP(fields[0]):
		// Định dạng hosts: cột đầu là IP đích, phần còn lại là hostname.
		return parseTokens(fields[1:])

	default:
		return nil, fmt.Errorf("%w: %d trường mà trường đầu không phải IP", ErrInvalid, len(fields))
	}
}

// stripComment bỏ chú thích và khoảng trắng thừa. Trả về chuỗi rỗng nếu dòng không còn
// nội dung.
func stripComment(line string) string {
	line = strings.TrimSpace(line)

	// "!" và ";" chỉ là chú thích khi đứng đầu dòng.
	if strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
		return ""
	}
	// "#" không bao giờ hợp lệ trong hostname nên cắt ở bất kỳ đâu.
	if i := strings.IndexByte(line, '#'); i >= 0 {
		line = line[:i]
	}
	return strings.TrimSpace(line)
}

// parseAdblock xử lý phần sau "||" của luật Adblock.
//
// "||example.com^" khớp domain và mọi subdomain, nên nó là wildcard chứ không phải
// exact. Hiểu nhầm chỗ này sẽ làm hụt phạm vi chặn so với ý định của nguồn.
func parseAdblock(rest string) ([]Rule, error) {
	// Bỏ modifier ("$important", "$third-party") và dấu kết thúc "^".
	if i := strings.IndexByte(rest, '$'); i >= 0 {
		rest = rest[:i]
	}
	rest = strings.TrimSuffix(rest, "^")
	rest = strings.TrimSuffix(rest, "/")

	// Luật Adblock có đường dẫn không phải luật cấp DNS; bỏ qua thay vì chặn nhầm
	// cả domain.
	if strings.ContainsAny(rest, "/*?=") {
		return nil, fmt.Errorf("%w: luật Adblock có đường dẫn hoặc ký tự đại diện", ErrInvalid)
	}

	d, err := Canonicalize(rest)
	if err != nil {
		return nil, err
	}
	return []Rule{{Domain: d, MatchType: Wildcard}}, nil
}

func parseTokens(tokens []string) ([]Rule, error) {
	rules := make([]Rule, 0, len(tokens))
	for _, tok := range tokens {
		r, err := parseToken(tok)
		if err != nil {
			// Một hostname hỏng làm hỏng cả dòng: dòng hosts là một khẳng định
			// duy nhất, chấp nhận một nửa sẽ khiến kết quả phụ thuộc thứ tự.
			return nil, err
		}
		rules = append(rules, r)
	}
	if len(rules) == 0 {
		return nil, ErrSkip
	}
	return rules, nil
}

// parseToken chuyển một token đơn thành Rule, tự nhận diện tiền tố wildcard.
func parseToken(tok string) (Rule, error) {
	mt := Exact

	switch {
	case strings.HasPrefix(tok, "*."):
		mt = Wildcard
		tok = tok[2:]
	case strings.HasPrefix(tok, "."):
		// Một số list dùng dấu chấm đầu để chỉ "domain này và mọi subdomain".
		mt = Wildcard
		tok = tok[1:]
	}

	if strings.Contains(tok, "*") {
		return Rule{}, fmt.Errorf("%w: dấu sao không nằm ở đầu", ErrInvalid)
	}

	d, err := Canonicalize(tok)
	if err != nil {
		return Rule{}, err
	}
	return Rule{Domain: d, MatchType: mt}, nil
}
