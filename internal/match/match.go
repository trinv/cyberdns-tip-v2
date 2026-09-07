// Package match tra cứu một domain trong tập rule, có tính tới quan hệ tổ tiên.
//
// Policy engine nhận vào các cờ danh sách đã giải quyết sẵn: nếu "*.example.com" nằm
// trong allowlist thì cờ của "shop.example.com" phải bằng true. Việc giải quyết đó là
// của package này.
//
// Tra cứu bằng SQL cho từng domain là không khả thi: ở mốc 10M domain nhân số category
// thì đó là hàng chục triệu lượt truy vấn cho mỗi lượt chạy policy. Các danh sách này
// nhỏ — hàng trăm tới hàng nghìn mục — nên nạp hết vào bộ nhớ rồi tra tại chỗ.
package match

import (
	"strings"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// Matcher là tập rule bất biến, an toàn khi dùng đồng thời từ nhiều goroutine sau khi
// dựng xong.
type Matcher struct {
	exact map[string]struct{}
	// wildcard khớp chính domain đó VÀ mọi domain con của nó.
	wildcard map[string]struct{}
}

// New dựng Matcher rỗng.
func New() *Matcher {
	return &Matcher{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}
}

// Add thêm một rule. domain phải đã qua domainname.Canonicalize.
func (m *Matcher) Add(domain string, mt domainname.MatchType) {
	if domain == "" {
		return
	}
	if mt == domainname.Wildcard {
		m.wildcard[domain] = struct{}{}
		return
	}
	m.exact[domain] = struct{}{}
}

// Len trả về số rule đã nạp.
func (m *Matcher) Len() int { return len(m.exact) + len(m.wildcard) }

// Empty báo Matcher không có rule nào. Kiểm tra trước khi gọi Match trong vòng lặp lớn
// giúp bỏ qua hẳn phần đi ngược cây.
func (m *Matcher) Empty() bool { return m == nil || m.Len() == 0 }

// Match cho biết domain có bị tập rule này bao phủ hay không.
//
// Khớp đúng tên, hoặc rule wildcard đặt tại chính domain đó hoặc tại bất kỳ tổ tiên
// nào của nó.
func (m *Matcher) Match(domain string) bool {
	if m.Empty() || domain == "" {
		return false
	}
	if _, ok := m.exact[domain]; ok {
		return true
	}

	// Đi ngược lên cây: example.com -> com. Cắt theo dấu chấm chứ không so tiền tố,
	// nếu không "example.com" sẽ khớp nhầm "notexample.com".
	for d := domain; d != ""; {
		if _, ok := m.wildcard[d]; ok {
			return true
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return false
}

// MatchRule tra cứu một rule đã chuẩn hóa.
//
// Rule wildcard cũng bị coi là được bao phủ khi có wildcard ở tổ tiên: chặn
// "*.example.com" thì "*.sub.example.com" là thừa.
func (m *Matcher) MatchRule(r domainname.Rule) bool { return m.Match(r.Domain) }
