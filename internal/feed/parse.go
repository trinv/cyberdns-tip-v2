package feed

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/psl"
)

// maxLineBytes: một dòng dài hơn thế này nghĩa là phản hồi không phải blocklist theo
// dòng — nhiều khả năng là trang HTML lỗi hoặc trang đăng nhập của captive portal.
const maxLineBytes = 1 << 20

var (
	ErrEmptyFeed       = errors.New("feed không có bản ghi hợp lệ nào")
	ErrTooManyRejects  = errors.New("tỉ lệ dòng lỗi vượt ngưỡng")
	ErrChangeTooLarge  = errors.New("số bản ghi biến động vượt ngưỡng")
	ErrNotLineOriented = errors.New("nội dung không phải danh sách theo dòng")
)

// Stats là kết quả thống kê của một lần parse.
type Stats struct {
	Lines    int
	Skipped  int // chú thích, dòng trống — KHÔNG tính là lỗi
	Accepted int
	Rejected int

	RejectReasons map[string]int
}

// RejectRatio là tỉ lệ dòng lỗi trên tổng số dòng có nội dung.
//
// Dòng bỏ qua không nằm ở mẫu số: một feed nhiều chú thích không được vì thế mà bị từ
// chối oan.
func (s Stats) RejectRatio() float64 {
	meaningful := s.Accepted + s.Rejected
	if meaningful == 0 {
		return 0
	}
	return float64(s.Rejected) / float64(meaningful)
}

// TopRejectReasons trả về các lý do lỗi phổ biến nhất, để ghi vào audit import.
func (s Stats) TopRejectReasons(n int) []string {
	type kv struct {
		reason string
		count  int
	}
	all := make([]kv, 0, len(s.RejectReasons))
	for r, c := range s.RejectReasons {
		all = append(all, kv{r, c})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].count != all[j].count {
			return all[i].count > all[j].count
		}
		return all[i].reason < all[j].reason // phá hòa ổn định
	})

	out := make([]string, 0, n)
	for i, e := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s=%d", e.reason, e.count))
	}
	return out
}

// Sink nhận từng rule đã chuẩn hóa cùng dòng thô sinh ra nó.
//
// Dòng thô đi kèm vì tầng L0 lưu bằng chứng đúng như nguồn công bố; không giữ nó thì
// không dựng lại được L1 sau khi sửa lỗi parser.
type Sink func(rule domainname.Rule, rawLine string) error

// Parse đọc feed theo dòng và đẩy từng rule hợp lệ sang sink.
//
// Rule quá rộng (public suffix) làm hỏng NGAY cả lần parse chứ không chỉ bị bỏ qua:
// một dòng "com" trong feed là dấu hiệu nguồn hỏng hoặc bị can thiệp, và fail-closed
// nghĩa là từ chối trọn lần import rồi giữ snapshot cũ.
func Parse(r io.Reader, sink Sink) (Stats, error) {
	st := Stats{RejectReasons: map[string]int{}}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLineBytes)

	for sc.Scan() {
		line := sc.Text()
		st.Lines++

		// NUL byte nghĩa là ta đang đọc nhị phân, không phải blocklist.
		if bytes.IndexByte(sc.Bytes(), 0) >= 0 {
			return st, fmt.Errorf("%w: gặp byte NUL ở dòng %d", ErrNotLineOriented, st.Lines)
		}

		rules, err := domainname.ParseLine(line)
		switch {
		case errors.Is(err, domainname.ErrSkip):
			st.Skipped++
			continue
		case err != nil:
			// Trước khi coi đây chỉ là một dòng lỗi bình thường, phải soi qua hàng rào
			// PSL. Canonicalize từ chối tên một nhãn ("com", "vn") vì lý do cú pháp,
			// nên nếu không kiểm tra ở đây thì dòng nguy hiểm nhất có thể có trong một
			// feed lại lọt qua như một lỗi vặt, trong khi "com.vn" hai nhãn thì làm
			// hỏng cả lần import. Không thể để hai trường hợp đó xử lý khác nhau.
			if broad := publicSuffixIn(line); broad != nil {
				return st, fmt.Errorf("dòng %d: %w", st.Lines, broad)
			}
			st.Rejected++
			st.RejectReasons[reasonOf(err)]++
			continue
		}

		for _, rule := range rules {
			if err := psl.Guard(rule.Domain); err != nil {
				return st, fmt.Errorf("dòng %d: %w", st.Lines, err)
			}
			if err := sink(rule, line); err != nil {
				return st, fmt.Errorf("dòng %d: %w", st.Lines, err)
			}
			st.Accepted++
		}
	}

	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return st, fmt.Errorf("%w: có dòng dài hơn %d byte", ErrNotLineOriented, maxLineBytes)
		}
		return st, fmt.Errorf("đọc feed: %w", err)
	}
	return st, nil
}

// publicSuffixIn soi từng token của một dòng đã bị từ chối, tìm rule quá rộng.
//
// Quét theo trường để bắt được cả dạng hosts ("0.0.0.0 com") lẫn dạng có chú thích
// ("com # ghi chú").
func publicSuffixIn(line string) error {
	for _, field := range strings.Fields(line) {
		r := psl.CheckRaw(field)
		if r.Verdict == psl.Rejected {
			return &psl.ErrTooBroad{Domain: field, Suffix: r.Suffix, Reason: r.Reason}
		}
	}
	return nil
}

// reasonOf gom lỗi thành nhãn ngắn dùng làm label metric. Không được dùng thẳng thông
// điệp lỗi: nó chứa cả tên domain và sẽ làm nổ số lượng chuỗi label.
func reasonOf(err error) string {
	switch {
	case errors.Is(err, domainname.ErrIP):
		return "is_ip"
	case errors.Is(err, domainname.ErrInvalid):
		return "invalid_hostname"
	default:
		return "unknown"
	}
}

// Validate quyết định một lần import có được chấp nhận hay không.
//
// previousAccepted là số bản ghi của lần import thành công gần nhất; truyền 0 khi đây
// là lần đầu.
func Validate(src Source, st Stats, previousAccepted int) error {
	src = src.withDefaults()

	// Feed rỗng gần như luôn là lỗi phía nguồn hoặc trang lỗi trả về 200. Áp dụng nó
	// sẽ gỡ chặn toàn bộ những gì nguồn này từng đóng góp.
	if st.Accepted == 0 {
		return fmt.Errorf("%w (đọc %d dòng, %d bỏ qua, %d lỗi)",
			ErrEmptyFeed, st.Lines, st.Skipped, st.Rejected)
	}

	if ratio := st.RejectRatio(); ratio > src.MaxRejectRatio {
		return fmt.Errorf("%w: %.1f%% > %.1f%% (%s)",
			ErrTooManyRejects, ratio*100, src.MaxRejectRatio*100,
			strings.Join(st.TopRejectReasons(3), " "))
	}

	if previousAccepted > 0 {
		delta := st.Accepted - previousAccepted
		if delta < 0 {
			delta = -delta
		}
		if ratio := float64(delta) / float64(previousAccepted); ratio > src.MaxChangeRatio {
			return fmt.Errorf("%w: %d -> %d (%.1f%% > %.1f%%)",
				ErrChangeTooLarge, previousAccepted, st.Accepted,
				ratio*100, src.MaxChangeRatio*100)
		}
	}

	return nil
}
