package match

import (
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

func build(entries ...[2]string) *Matcher {
	m := New()
	for _, e := range entries {
		mt := domainname.Exact
		if e[1] == "wildcard" {
			mt = domainname.Wildcard
		}
		m.Add(e[0], mt)
	}
	return m
}

func TestExactMatch(t *testing.T) {
	m := build([2]string{"example.com", "exact"})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},
		// Rule exact KHÔNG bao phủ domain con.
		{"shop.example.com", false},
		{"example.net", false},
		{"notexample.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, muốn %v", tt.domain, got, tt.want)
		}
	}
}

func TestWildcardMatchesSelfAndDescendants(t *testing.T) {
	m := build([2]string{"example.com", "wildcard"})

	tests := []struct {
		domain string
		want   bool
	}{
		{"example.com", true},       // chính nó
		{"shop.example.com", true},  // con
		{"a.b.c.example.com", true}, // cháu chắt
		{"example.net", false},
		{"com", false},
		// Bẫy tiền tố: cắt theo dấu chấm chứ không so chuỗi.
		{"notexample.com", false},
		{"myexample.com", false},
	}
	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, muốn %v", tt.domain, got, tt.want)
		}
	}
}

// Đây là tình huống D2 trong bảng xung đột: tenant cho phép một domain con nằm dưới
// một rule cha đang bị chặn.
func TestDeepAncestorMatch(t *testing.T) {
	m := build([2]string{"example.com", "wildcard"})

	deep := "a.b.c.d.e.f.g.shop.example.com"
	if !m.Match(deep) {
		t.Errorf("Match(%q) = false, muốn true: tổ tiên xa vẫn phải bao phủ", deep)
	}
}

func TestMixedRules(t *testing.T) {
	m := build(
		[2]string{"exact.example.com", "exact"},
		[2]string{"wild.example.com", "wildcard"},
	)

	tests := []struct {
		domain string
		want   bool
	}{
		{"exact.example.com", true},
		{"sub.exact.example.com", false}, // exact không bao phủ con
		{"wild.example.com", true},
		{"sub.wild.example.com", true},
		{"example.com", false}, // không rule nào đặt ở đây
	}
	for _, tt := range tests {
		if got := m.Match(tt.domain); got != tt.want {
			t.Errorf("Match(%q) = %v, muốn %v", tt.domain, got, tt.want)
		}
	}
}

func TestEmptyMatcher(t *testing.T) {
	if !New().Empty() {
		t.Error("Matcher mới phải rỗng")
	}
	if New().Match("example.com") {
		t.Error("Matcher rỗng không được khớp gì")
	}

	// Con trỏ nil phải an toàn: bên gọi có thể chưa nạp danh sách nào.
	var nilM *Matcher
	if !nilM.Empty() {
		t.Error("Matcher nil phải rỗng")
	}
	if nilM.Match("example.com") {
		t.Error("Matcher nil không được khớp gì")
	}
}

func TestAddIgnoresEmptyDomain(t *testing.T) {
	m := New()
	m.Add("", domainname.Exact)
	m.Add("", domainname.Wildcard)
	if !m.Empty() {
		t.Errorf("Len() = %d sau khi thêm chuỗi rỗng, muốn 0", m.Len())
	}
}

func TestMatchRule(t *testing.T) {
	m := build([2]string{"example.com", "wildcard"})

	// Rule wildcard con cũng bị tổ tiên bao phủ: chặn "*.example.com" thì
	// "*.sub.example.com" là thừa.
	if !m.MatchRule(domainname.Rule{Domain: "sub.example.com", MatchType: domainname.Wildcard}) {
		t.Error("rule wildcard con không bị tổ tiên wildcard bao phủ")
	}
	if !m.MatchRule(domainname.Rule{Domain: "sub.example.com", MatchType: domainname.Exact}) {
		t.Error("rule exact con không bị tổ tiên wildcard bao phủ")
	}
}

func TestSingleLabelDoesNotPanic(t *testing.T) {
	// Canonicalize đã loại tên một nhãn, nhưng Matcher không được sập nếu gặp.
	m := build([2]string{"com", "wildcard"})
	if !m.Match("com") {
		t.Error("Match(com) = false")
	}
	if !m.Match("example.com") {
		t.Error("Match(example.com) = false khi có wildcard ở com")
	}
}

func BenchmarkMatchDeep(b *testing.B) {
	m := build([2]string{"example.com", "wildcard"})
	domain := "a.b.c.d.e.f.g.h.shop.example.com"
	for b.Loop() {
		m.Match(domain)
	}
}

func BenchmarkMatchMiss(b *testing.B) {
	m := New()
	// Nghìn mục là quy mô thực tế của allowlist toàn cục.
	for i := range 1000 {
		m.Add(string(rune('a'+i%26))+"blocked.example.com", domainname.Wildcard)
	}
	for b.Loop() {
		m.Match("a.b.c.unrelated.example.net")
	}
}
