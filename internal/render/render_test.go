package render

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

func exact(d string) domainname.Rule { return domainname.Rule{Domain: d, MatchType: domainname.Exact} }
func wildcard(d string) domainname.Rule {
	return domainname.Rule{Domain: d, MatchType: domainname.Wildcard}
}

func domains(rules []domainname.Rule) []string {
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = r.Domain + "|" + r.MatchType.String()
	}
	return out
}

func TestCollapse(t *testing.T) {
	tests := []struct {
		name string
		in   []domainname.Rule
		want []string
	}{
		{
			// Xung đột A2: wildcard cùng domain nuốt bản exact.
			name: "wildcard phủ exact cùng domain",
			in:   []domainname.Rule{exact("example.com"), wildcard("example.com")},
			want: []string{"example.com|wildcard"},
		},
		{
			// Xung đột A3: feed A chặn cha, feed B chặn con.
			name: "cha wildcard phủ con",
			in:   []domainname.Rule{wildcard("example.com"), exact("evil.example.com")},
			want: []string{"example.com|wildcard"},
		},
		{
			name: "cha exact cũng phủ con ở định dạng phủ cây con",
			in:   []domainname.Rule{exact("example.com"), exact("a.b.example.com")},
			want: []string{"example.com|exact"},
		},
		{
			name: "phủ nhiều tầng",
			in: []domainname.Rule{
				wildcard("example.com"),
				exact("a.example.com"),
				exact("b.a.example.com"),
				wildcard("c.b.a.example.com"),
			},
			want: []string{"example.com|wildcard"},
		},
		{
			// Bẫy tiền tố: "example.com" không được nuốt "exampleother.com".
			name: "không nuốt domain chỉ trùng tiền tố",
			in:   []domainname.Rule{exact("example.com"), exact("exampleother.com")},
			want: []string{"example.com|exact", "exampleother.com|exact"},
		},
		{
			name: "anh em không phủ nhau",
			in:   []domainname.Rule{exact("a.example.com"), exact("b.example.com")},
			want: []string{"a.example.com|exact", "b.example.com|exact"},
		},
		{
			name: "TLD khác nhau độc lập",
			in:   []domainname.Rule{exact("example.com"), exact("example.net"), exact("example.vn")},
			want: []string{"example.com|exact", "example.net|exact", "example.vn|exact"},
		},
		{
			name: "bỏ trùng lặp hệt nhau",
			in:   []domainname.Rule{exact("example.com"), exact("example.com")},
			want: []string{"example.com|exact"},
		},
		{
			name: "rỗng",
			in:   nil,
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domains(Collapse(tt.in, FormatDomain))
			if !slices.Equal(got, tt.want) {
				t.Errorf("Collapse() = %v, muốn %v", got, tt.want)
			}
		})
	}
}

// Collapse không được sửa slice của bên gọi: cùng một tập rule còn phải dùng để dựng
// file cho nhiều tenant.
func TestCollapseDoesNotMutateInput(t *testing.T) {
	in := []domainname.Rule{exact("b.example.com"), wildcard("example.com"), exact("a.example.com")}
	before := slices.Clone(in)

	Collapse(in, FormatDomain)

	if !slices.Equal(in, before) {
		t.Errorf("Collapse sửa đầu vào: %v -> %v", before, in)
	}
}

// Thứ tự đầu vào không được ảnh hưởng kết quả: CSDL không bảo đảm thứ tự hàng, và
// checksum phải ổn định giữa các lần dựng.
func TestCollapseIsOrderIndependent(t *testing.T) {
	in := []domainname.Rule{
		exact("evil.example.com"),
		wildcard("example.com"),
		exact("other.net"),
		exact("a.other.net"),
	}

	want := domains(Collapse(in, FormatDomain))

	reversed := slices.Clone(in)
	slices.Reverse(reversed)
	if got := domains(Collapse(reversed, FormatDomain)); !slices.Equal(got, want) {
		t.Errorf("đảo thứ tự đổi kết quả: %v vs %v", got, want)
	}
}

func TestRenderFormats(t *testing.T) {
	rules := []domainname.Rule{exact("b.example.com"), exact("a.example.com")}

	t.Run("domain", func(t *testing.T) {
		b, err := Render(rules, FormatDomain)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if got := string(b.Bytes); got != "a.example.com\nb.example.com\n" {
			t.Errorf("nội dung = %q", got)
		}
		if b.Entries != 2 {
			t.Errorf("Entries = %d, muốn 2", b.Entries)
		}
	})

	t.Run("wildcard", func(t *testing.T) {
		b, err := Render(rules, FormatWildcard)
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
		if got := string(b.Bytes); got != "*.a.example.com\n*.b.example.com\n" {
			t.Errorf("nội dung = %q", got)
		}
	})

	t.Run("định dạng lạ", func(t *testing.T) {
		if _, err := Render(rules, Format("rpz")); err == nil {
			t.Error("Render chấp nhận định dạng chưa hỗ trợ, muốn lỗi")
		}
	})
}

// Checksum chỉ băm phần nội dung. Nếu tính cả header (có chứa thời điểm dựng) thì mỗi
// lần chạy sẽ ra giá trị khác dù dữ liệu không đổi — phá vỡ cả "chỉ regenerate khi dữ
// liệu thực sự thay đổi" lẫn tính ổn định của ETag.
func TestChecksumIsStableAcrossBuilds(t *testing.T) {
	rules := []domainname.Rule{exact("a.example.com"), exact("b.example.com")}

	first, err := Render(rules, FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	shuffled := []domainname.Rule{exact("b.example.com"), exact("a.example.com")}
	second, err := Render(shuffled, FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	if first.Checksum != second.Checksum {
		t.Errorf("checksum đổi khi chỉ đảo thứ tự đầu vào: %s vs %s",
			first.Checksum, second.Checksum)
	}
	if !strings.HasPrefix(first.Checksum, "sha256:") {
		t.Errorf("checksum = %q, muốn có tiền tố sha256:", first.Checksum)
	}

	// Nội dung đổi thật thì checksum phải đổi.
	third, err := Render(append(slices.Clone(rules), exact("c.example.com")), FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if third.Checksum == first.Checksum {
		t.Error("checksum không đổi dù đã thêm một domain")
	}
}

func TestWriteTo(t *testing.T) {
	body, err := Render([]domainname.Rule{exact("evil.example.com")}, FormatDomain)
	if err != nil {
		t.Fatalf("Render: %v", err)
	}

	var buf bytes.Buffer
	n, err := WriteTo(&buf, Header{
		Version:     "2026-09-07T03-00Z-abc123",
		GeneratedAt: "2026-09-07T03:00:00Z",

		Entries:     body.Entries,
		Checksum:    body.Checksum,
		Attribution: []string{"hagezi-tif (GPL-3.0)"},
	}, body)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	out := buf.String()
	if int64(len(out)) != n {
		t.Errorf("số byte trả về %d, thực tế ghi %d", n, len(out))
	}

	for _, want := range []string{

		"# Version: 2026-09-07T03-00Z-abc123",
		"# Checksum: " + body.Checksum,
		"# Source: hagezi-tif (GPL-3.0)",
		"evil.example.com\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("đầu ra thiếu %q\ncó:\n%s", want, out)
		}
	}

	// Mọi dòng header phải là chú thích, nếu không Blocky sẽ coi chúng là domain.
	for _, l := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		if l == "evil.example.com" {
			break
		}
		if !strings.HasPrefix(l, "#") {
			t.Errorf("dòng header %q không phải chú thích", l)
		}
	}
}
