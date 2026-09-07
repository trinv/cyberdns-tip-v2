package domainname

import (
	"errors"
	"testing"
)

func TestCanonicalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"đã chuẩn", "example.com", "example.com"},
		{"chữ hoa", "EXAMPLE.COM", "example.com"},
		{"chữ hoa lẫn lộn", "ExAmPlE.CoM", "example.com"},
		{"dấu chấm cuối", "example.com.", "example.com"},
		{"khoảng trắng thừa", "  example.com  ", "example.com"},
		{"subdomain nhiều tầng", "a.b.c.example.com", "a.b.c.example.com"},
		{"gạch ngang", "my-site.example.com", "my-site.example.com"},

		// Gạch dưới xuất hiện thật trong blocklist (_dmarc, _dnslink). Hồ sơ IDNA
		// nghiêm ngặt sẽ loại bỏ chúng âm thầm.
		{"nhãn có gạch dưới", "_dmarc.example.com", "_dmarc.example.com"},

		// IDN phải quy về một dạng duy nhất, nếu không cùng một domain sẽ thành hai hàng.
		{"IDN tiếng Đức", "bücher.de", "xn--bcher-kva.de"},
		{"IDN đã là punycode", "xn--bcher-kva.de", "xn--bcher-kva.de"},
		{"IDN punycode chữ hoa", "XN--BCHER-KVA.DE", "xn--bcher-kva.de"},
		{"IDN tiếng Việt", "tênmiền.vn", "xn--tnmin-hsa0954c.vn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Canonicalize(tt.in)
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("Canonicalize(%q) = %q, muốn %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"IPv4", "192.168.1.1", ErrIP},
		{"IPv4 số 0", "0.0.0.0", ErrIP},
		{"IPv6", "::1", ErrIP},
		{"IPv6 đầy đủ", "2001:db8::1", ErrIP},
		{"IPv6 trong ngoặc", "[::1]", ErrIP},

		{"rỗng", "", ErrInvalid},
		{"chỉ khoảng trắng", "   ", ErrInvalid},
		{"một nhãn", "localhost", ErrInvalid},
		{"TLD trần", "com", ErrInvalid},
		{"nhãn rỗng ở giữa", "a..b.com", ErrInvalid},
		{"bắt đầu bằng dấu chấm", ".example.com", ErrInvalid},
		{"có khoảng trắng", "exa mple.com", ErrInvalid},
		{"có dấu gạch chéo", "example.com/path", ErrInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Canonicalize(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Canonicalize(%q) lỗi = %v, muốn %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

func TestCanonicalizeLengthLimits(t *testing.T) {
	label64 := ""
	for range 64 {
		label64 += "a"
	}
	if _, err := Canonicalize(label64 + ".com"); !errors.Is(err, ErrInvalid) {
		t.Errorf("nhãn 64 ký tự được chấp nhận, muốn ErrInvalid")
	}

	label63 := label64[:63]
	if _, err := Canonicalize(label63 + ".com"); err != nil {
		t.Errorf("nhãn 63 ký tự bị từ chối: %v", err)
	}

	long := ""
	for range 50 {
		long += "abcde."
	}
	long += "com" // vượt 253 byte
	if _, err := Canonicalize(long); !errors.Is(err, ErrInvalid) {
		t.Errorf("tên dài %d byte được chấp nhận, muốn ErrInvalid", len(long))
	}
}

func TestParseLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []Rule
	}{
		{"domain trần", "example.com", []Rule{{"example.com", Exact}}},
		{"wildcard dấu sao", "*.example.com", []Rule{{"example.com", Wildcard}}},
		{"wildcard dấu chấm đầu", ".example.com", []Rule{{"example.com", Wildcard}}},

		{"hosts 0.0.0.0", "0.0.0.0 example.com", []Rule{{"example.com", Exact}}},
		{"hosts 127.0.0.1", "127.0.0.1 example.com", []Rule{{"example.com", Exact}}},
		{"hosts IPv6", ":: example.com", []Rule{{"example.com", Exact}}},
		{"hosts nhiều tab", "0.0.0.0\t\texample.com", []Rule{{"example.com", Exact}}},

		// Dòng hosts nhiều hostname là thật; chỉ lấy phần tử đầu sẽ bỏ sót domain.
		{
			"hosts nhiều hostname",
			"0.0.0.0 a.example.com b.example.com c.example.com",
			[]Rule{
				{"a.example.com", Exact},
				{"b.example.com", Exact},
				{"c.example.com", Exact},
			},
		},
		{"hosts kèm wildcard", "0.0.0.0 *.example.com", []Rule{{"example.com", Wildcard}}},

		// "||domain^" của Adblock khớp cả subdomain, nên phải là wildcard.
		{"adblock", "||example.com^", []Rule{{"example.com", Wildcard}}},
		{"adblock không có mũ", "||example.com", []Rule{{"example.com", Wildcard}}},
		{"adblock có modifier", "||example.com^$important", []Rule{{"example.com", Wildcard}}},
		{"adblock third-party", "||ads.example.com^$third-party", []Rule{{"ads.example.com", Wildcard}}},

		{"chú thích cuối dòng", "example.com # ghi chú", []Rule{{"example.com", Exact}}},
		{"chuẩn hóa khi parse", "  *.EXAMPLE.COM.  ", []Rule{{"example.com", Wildcard}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseLine(tt.in)
			if err != nil {
				t.Fatalf("ParseLine(%q): %v", tt.in, err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("ParseLine(%q) = %v, muốn %v", tt.in, got, tt.want)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Errorf("ParseLine(%q)[%d] = %+v, muốn %+v", tt.in, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseLineSkips(t *testing.T) {
	// Dòng bỏ qua KHÔNG được tính vào tỉ lệ lỗi parse, nếu không một feed nhiều chú
	// thích sẽ bị từ chối oan bởi ngưỡng lỗi.
	for _, in := range []string{
		"",
		"   ",
		"# chú thích kiểu hosts",
		"! chú thích kiểu Adblock",
		"; chú thích kiểu ini",
		"  # thụt đầu dòng",
		"#",
	} {
		t.Run(in, func(t *testing.T) {
			if _, err := ParseLine(in); !errors.Is(err, ErrSkip) {
				t.Errorf("ParseLine(%q) lỗi = %v, muốn ErrSkip", in, err)
			}
		})
	}
}

func TestParseLineRejects(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantErr error
	}{
		{"chỉ có IP", "192.168.1.1", ErrIP},
		{"hosts trỏ tới IP", "0.0.0.0 127.0.0.1", ErrIP},
		{"adblock có đường dẫn", "||example.com/ads.js^", ErrInvalid},
		{"adblock có ký tự đại diện", "||*.doubleclick.net^", ErrInvalid},
		{"sao ở giữa", "ads.*.example.com", ErrInvalid},
		{"hai token không phải hosts", "example.com foo.com", ErrInvalid},
		{"chỉ có một nhãn", "localhost", ErrInvalid},

		// Một hostname hỏng làm hỏng cả dòng: dòng hosts là một khẳng định duy nhất,
		// chấp nhận một nửa sẽ khiến kết quả phụ thuộc thứ tự.
		{"hosts có phần tử hỏng", "0.0.0.0 good.example.com bad..com", ErrInvalid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseLine(tt.in)
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("ParseLine(%q) lỗi = %v, muốn %v", tt.in, err, tt.wantErr)
			}
		})
	}
}

// Bài test cốt lõi của xung đột A7, lấy thẳng từ mục Verification của kế hoạch: cùng
// một domain viết theo nhiều cách phải quy về đúng MỘT rule.
func TestSameDomainManyRepresentationsCollapseToOne(t *testing.T) {
	exact := []string{
		"example.com",
		"EXAMPLE.COM",
		"example.com.",
		"  example.com  ",
		"0.0.0.0 example.com",
		"127.0.0.1\texample.com",
		"example.com # kèm chú thích",
	}

	seen := map[Rule]bool{}
	for _, line := range exact {
		rules, err := ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine(%q): %v", line, err)
		}
		for _, r := range rules {
			seen[r] = true
		}
	}

	if len(seen) != 1 {
		t.Fatalf("%d rule khác nhau từ %d cách viết cùng một domain: %v",
			len(seen), len(exact), seen)
	}
	if !seen[Rule{"example.com", Exact}] {
		t.Errorf("rule thu được = %v, muốn {example.com exact}", seen)
	}

	// Các cách viết wildcard cũng phải gộp về một, và phải KHÁC với rule exact:
	// claude_rm.md coi exact và wildcard là hai enforcement rule khác nhau.
	wildcard := []string{"*.example.com", ".example.com", "||example.com^", "*.EXAMPLE.COM."}
	seenW := map[Rule]bool{}
	for _, line := range wildcard {
		rules, err := ParseLine(line)
		if err != nil {
			t.Fatalf("ParseLine(%q): %v", line, err)
		}
		for _, r := range rules {
			seenW[r] = true
		}
	}

	if len(seenW) != 1 {
		t.Fatalf("%d rule wildcard khác nhau từ %d cách viết: %v", len(seenW), len(wildcard), seenW)
	}
	if !seenW[Rule{"example.com", Wildcard}] {
		t.Errorf("rule wildcard = %v, muốn {example.com wildcard}", seenW)
	}
}

// Chuẩn hóa phải lũy đẳng: chạy lại trên kết quả của chính nó không được đổi gì.
// Không có tính chất này thì việc dựng lại L1 từ L0 sẽ trôi dần qua mỗi lần chạy.
func TestCanonicalizeIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"example.com", "EXAMPLE.COM.", "bücher.de", "_dmarc.example.com",
		"a.b.c.example.co.uk", "tênmiền.vn",
	} {
		t.Run(in, func(t *testing.T) {
			once, err := Canonicalize(in)
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", in, err)
			}
			twice, err := Canonicalize(once)
			if err != nil {
				t.Fatalf("Canonicalize(%q): %v", once, err)
			}
			if once != twice {
				t.Errorf("không lũy đẳng: %q -> %q -> %q", in, once, twice)
			}
		})
	}
}

func TestMatchTypeString(t *testing.T) {
	// Giá trị số phải khớp cột match_type trong CSDL.
	if Exact != 0 || Wildcard != 1 {
		t.Fatalf("Exact=%d Wildcard=%d, muốn 0 và 1 cho khớp lược đồ", Exact, Wildcard)
	}
	if Exact.String() != "exact" || Wildcard.String() != "wildcard" {
		t.Errorf("String() = %q/%q", Exact.String(), Wildcard.String())
	}
}
