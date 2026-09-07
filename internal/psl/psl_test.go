package psl

import (
	"errors"
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

func TestCheckRejectsICANNSuffixes(t *testing.T) {
	// Mỗi dòng ở đây, nếu lọt vào blocklist, sẽ chặn nguyên một TLD.
	for _, d := range []string{
		"com", "net", "org", "info",
		"vn", "com.vn", "edu.vn", "gov.vn",
		"co.uk", "org.uk",
		"com.au", "co.jp",
	} {
		t.Run(d, func(t *testing.T) {
			r := Check(d)
			if r.Verdict != Rejected {
				t.Errorf("Check(%q).Verdict = %v, muốn Rejected", d, r.Verdict)
			}
			if r.Suffix != d {
				t.Errorf("Check(%q).Suffix = %q, muốn %q", d, r.Suffix, d)
			}
		})
	}
}

func TestCheckAllowsNormalDomains(t *testing.T) {
	for _, d := range []string{
		"example.com",
		"evil.example.com",
		"a.b.c.example.com",
		"vnnic.vn",
		"tenmien.com.vn",
		"something.co.uk",
		"xn--bcher-kva.de",
		"_dmarc.example.com",
	} {
		t.Run(d, func(t *testing.T) {
			if r := Check(d); r.Verdict != OK {
				t.Errorf("Check(%q).Verdict = %v (%s), muốn OK", d, r.Verdict, r.Reason)
			}
			if err := Guard(d); err != nil {
				t.Errorf("Guard(%q) = %v, muốn nil", d, err)
			}
		})
	}
}

// Public suffix thuộc phần private không bị từ chối thẳng: chặn cả một nền tảng hosting
// miễn phí đôi khi đúng là chủ ý. Nhưng phải có người duyệt.
func TestCheckFlagsPrivateSuffixesForReview(t *testing.T) {
	for _, d := range []string{"blogspot.com", "github.io"} {
		t.Run(d, func(t *testing.T) {
			r := Check(d)
			if r.Verdict != ReviewRequired {
				t.Errorf("Check(%q).Verdict = %v, muốn ReviewRequired", d, r.Verdict)
			}
			// Guard cho qua; quyết định là của policy, không phải của tầng ingest.
			if err := Guard(d); err != nil {
				t.Errorf("Guard(%q) = %v, muốn nil (chỉ cần gắn cờ chờ duyệt)", d, err)
			}
		})
	}

	// Nhưng một site cụ thể TRÊN nền tảng đó thì chặn bình thường.
	if r := Check("evil.blogspot.com"); r.Verdict != OK {
		t.Errorf("Check(evil.blogspot.com) = %v, muốn OK", r.Verdict)
	}
}

func TestGuardErrorCarriesContext(t *testing.T) {
	err := Guard("com")
	if err == nil {
		t.Fatal("Guard(com) = nil, muốn lỗi")
	}

	var tooBroad *ErrTooBroad
	if !errors.As(err, &tooBroad) {
		t.Fatalf("lỗi = %T, muốn *ErrTooBroad", err)
	}
	if tooBroad.Domain != "com" || tooBroad.Suffix != "com" {
		t.Errorf("lỗi = %+v, muốn nêu domain và suffix", tooBroad)
	}
}

// Hàng rào chỉ có tác dụng khi đặt SAU bước chuẩn hóa: "COM." và "com" phải cùng bị
// chặn, nếu không một feed hỏng chỉ cần viết hoa là lọt qua.
func TestGuardAfterCanonicalizeCatchesVariants(t *testing.T) {
	// Canonicalize từ chối tên một nhãn trước cả khi tới PSL, nên "COM." dừng ở đó.
	if _, err := domainname.Canonicalize("COM."); !errors.Is(err, domainname.ErrInvalid) {
		t.Errorf("Canonicalize(COM.) = %v, muốn ErrInvalid", err)
	}

	// Suffix nhiều nhãn thì qua được Canonicalize, nên PSL mới là lớp chặn thật sự.
	for _, raw := range []string{"COM.VN", "com.vn.", "  com.vn  "} {
		d, err := domainname.Canonicalize(raw)
		if err != nil {
			t.Fatalf("Canonicalize(%q): %v", raw, err)
		}
		if err := Guard(d); err == nil {
			t.Errorf("Guard(%q -> %q) = nil, muốn bị từ chối", raw, d)
		}
	}
}
