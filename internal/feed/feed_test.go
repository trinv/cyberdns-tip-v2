package feed

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

func testFetcher() *Fetcher {
	f := NewFetcher()
	// Test không được chờ backoff thật.
	f.Sleep = func(time.Duration) {}
	f.Jitter = func() float64 { return 0 }
	return f
}

func testSource(url string) Source {
	return Source{ID: "test", Name: "test", URL: url, Timeout: 5 * time.Second}
}

func drain(t *testing.T, r *Response) string {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("đọc body: %v", err)
	}
	if err := r.Body.Close(); err != nil {
		t.Fatalf("đóng body: %v", err)
	}
	return string(raw)
}

func TestFetchOK(t *testing.T) {
	const content = "evil.example.com\nads.example.com\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `"abc123"`)
		w.Header().Set("Last-Modified", "Mon, 07 Sep 2026 03:00:00 GMT")
		fmt.Fprint(w, content)
	}))
	defer srv.Close()

	resp, err := testFetcher().Fetch(context.Background(), testSource(srv.URL), Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if got := drain(t, resp); got != content {
		t.Errorf("body = %q, muốn %q", got, content)
	}
	if resp.ETag != `"abc123"` {
		t.Errorf("ETag = %q", resp.ETag)
	}
	if resp.Bytes() != int64(len(content)) {
		t.Errorf("Bytes() = %d, muốn %d", resp.Bytes(), len(content))
	}
	if !strings.HasPrefix(resp.Hash(), "sha256:") {
		t.Errorf("Hash() = %q", resp.Hash())
	}
}

// Request có điều kiện là thứ tránh tải lại vô ích và tránh dựng lại snapshot khi không
// có gì đổi.
func TestFetchConditional(t *testing.T) {
	var gotINM, gotIMS string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotINM = r.Header.Get("If-None-Match")
		gotIMS = r.Header.Get("If-Modified-Since")
		w.WriteHeader(http.StatusNotModified)
	}))
	defer srv.Close()

	cond := Conditional{ETag: `"abc123"`, LastModified: "Mon, 07 Sep 2026 03:00:00 GMT"}
	_, err := testFetcher().Fetch(context.Background(), testSource(srv.URL), cond)

	if !errors.Is(err, ErrNotModified) {
		t.Fatalf("Fetch = %v, muốn ErrNotModified", err)
	}
	if gotINM != cond.ETag {
		t.Errorf("If-None-Match = %q, muốn %q", gotINM, cond.ETag)
	}
	if gotIMS != cond.LastModified {
		t.Errorf("If-Modified-Since = %q, muốn %q", gotIMS, cond.LastModified)
	}
}

func TestFetchRejectsOversizeByContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "10000")
		w.Write(make([]byte, 10000))
	}))
	defer srv.Close()

	src := testSource(srv.URL)
	src.MaxResponseBytes = 100

	// Content-Length đã vượt trần thì hỏng ngay, không tải hết rồi mới bỏ.
	if _, err := testFetcher().Fetch(context.Background(), src, Conditional{}); !errors.Is(err, ErrTooLarge) {
		t.Errorf("Fetch = %v, muốn ErrTooLarge", err)
	}
}

func TestFetchRejectsOversizeWhileStreaming(t *testing.T) {
	// Không khai báo Content-Length: trần phải được áp trong lúc đọc.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Transfer-Encoding", "chunked")
		for range 100 {
			w.Write([]byte(strings.Repeat("a", 1000)))
			w.(http.Flusher).Flush()
		}
	}))
	defer srv.Close()

	src := testSource(srv.URL)
	src.MaxResponseBytes = 5000

	resp, err := testFetcher().Fetch(context.Background(), src, Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	defer resp.Body.Close()

	if _, err := io.ReadAll(resp.Body); !errors.Is(err, ErrTooLarge) {
		t.Errorf("đọc body = %v, muốn ErrTooLarge", err)
	}
}

// Một feed tải được một nửa trông y hệt một feed vừa gỡ bỏ một nửa số domain. Không
// phát hiện thì mỗi lần mạng chập chờn sẽ thành một đợt gỡ chặn hàng loạt.
func TestFetchDetectsTruncatedResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.Write([]byte("chỉ có một phần"))
	}))
	defer srv.Close()

	resp, err := testFetcher().Fetch(context.Background(), testSource(srv.URL), Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	_, _ = io.ReadAll(resp.Body)
	if err := resp.Body.Close(); !errors.Is(err, ErrTruncated) {
		t.Errorf("Close() = %v, muốn ErrTruncated", err)
	}
}

func TestFetchRetries(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		wantCalls   int
		wantErrIs   error
		description string
	}{
		{"503 thử lại", http.StatusServiceUnavailable, 3, ErrTooManyTries, "5xx là lỗi tạm thời"},
		{"429 thử lại", http.StatusTooManyRequests, 3, ErrTooManyTries, "bị giới hạn tốc độ"},
		{"404 không thử lại", http.StatusNotFound, 1, ErrBadStatus, "thử lại 4xx là vô ích"},
		{"403 không thử lại", http.StatusForbidden, 1, ErrBadStatus, "thử lại 4xx là vô ích"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.WriteHeader(tt.status)
			}))
			defer srv.Close()

			src := testSource(srv.URL)
			src.MaxAttempts = 3

			_, err := testFetcher().Fetch(context.Background(), src, Conditional{})
			if !errors.Is(err, tt.wantErrIs) {
				t.Errorf("Fetch = %v, muốn %v", err, tt.wantErrIs)
			}
			if calls != tt.wantCalls {
				t.Errorf("gọi %d lần, muốn %d (%s)", calls, tt.wantCalls, tt.description)
			}
		})
	}
}

func TestFetchSucceedsAfterTransientFailure(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "evil.example.com\n")
	}))
	defer srv.Close()

	src := testSource(srv.URL)
	src.MaxAttempts = 3

	resp, err := testFetcher().Fetch(context.Background(), src, Conditional{})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := drain(t, resp); got != "evil.example.com\n" {
		t.Errorf("body = %q", got)
	}
}

func collect(t *testing.T, input string) ([]domainname.Rule, Stats, error) {
	t.Helper()
	var got []domainname.Rule
	st, err := Parse(strings.NewReader(input), func(r domainname.Rule, _ string) error {
		got = append(got, r)
		return nil
	})
	return got, st, err
}

func TestParse(t *testing.T) {
	input := strings.Join([]string{
		"# HaGeZi Threat Intelligence Feed",
		"!",
		"",
		"evil.example.com",
		"0.0.0.0 malware.example.com",
		"*.phish.example.com",
		"||ads.example.com^",
		"192.168.1.1",       // lỗi: là IP
		"không_hợp_lệ..com", // lỗi: nhãn rỗng
		"good.example.net",
	}, "\n")

	rules, st, err := collect(t, input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if st.Accepted != 5 {
		t.Errorf("Accepted = %d, muốn 5 (%v)", st.Accepted, rules)
	}
	if st.Rejected != 2 {
		t.Errorf("Rejected = %d, muốn 2", st.Rejected)
	}
	if st.Skipped != 3 {
		t.Errorf("Skipped = %d, muốn 3", st.Skipped)
	}

	if st.RejectReasons["is_ip"] != 1 {
		t.Errorf("RejectReasons[is_ip] = %d, muốn 1", st.RejectReasons["is_ip"])
	}
	if st.RejectReasons["invalid_hostname"] != 1 {
		t.Errorf("RejectReasons[invalid_hostname] = %d, muốn 1", st.RejectReasons["invalid_hostname"])
	}
}

// Dòng chú thích không được nằm ở mẫu số của tỉ lệ lỗi, nếu không một feed nhiều chú
// thích sẽ bị từ chối oan.
func TestRejectRatioExcludesSkippedLines(t *testing.T) {
	var comments []string
	for range 100 {
		comments = append(comments, "# chú thích")
	}
	input := strings.Join(comments, "\n") + "\nevil.example.com\n192.168.1.1\n"

	_, st, err := collect(t, input)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got := st.RejectRatio(); got != 0.5 {
		t.Errorf("RejectRatio() = %v, muốn 0.5 (1 lỗi trên 2 dòng có nội dung)", got)
	}
}

// Xung đột A8, đã hiệu chỉnh sau khi chạy trên feed thật.
//
// TLD trần là dấu hiệu hỏng không thể nhầm: không feed hợp lệ nào chặn nguyên một TLD.
// Trường hợp này vẫn làm hỏng cả lần import.
func TestBareTLDFailsWholeImport(t *testing.T) {
	for _, bad := range []string{"com", "vn", "net"} {
		t.Run(bad, func(t *testing.T) {
			_, _, err := collect(t, "good.example.com\n"+bad+"\nother.example.com\n")
			if !errors.Is(err, ErrBareTLD) {
				t.Errorf("Parse = %v, muốn ErrBareTLD", err)
			}
		})
	}
}

// Public suffix NHIỀU NHÃN thì chỉ bỏ dòng và đếm lại.
//
// Feed thật có chứa chúng một cách chủ ý: HaGeZi TIF có đúng 3 dòng như vậy trên
// 2,15 triệu (5g.in, 6g.in, firm.in). Vứt bỏ 2,15 triệu domain vì 3 dòng là đánh đổi
// sai; nhưng áp dụng chúng thì chặn cả một public suffix. Nên: bỏ qua, đếm, và đưa lên
// cho người duyệt.
func TestMultiLabelPublicSuffixIsSkippedNotFatal(t *testing.T) {
	rules, st, err := collect(t,
		"good.example.com\n*.5g.in\nco.uk\nother.example.net\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if st.PublicSuffix != 2 {
		t.Errorf("PublicSuffix = %d, muốn 2", st.PublicSuffix)
	}
	if st.Accepted != 2 {
		t.Errorf("Accepted = %d, muốn 2 (%v)", st.Accepted, rules)
	}
	for _, r := range rules {
		if r.Domain == "5g.in" || r.Domain == "co.uk" {
			t.Errorf("rule public suffix %q vẫn lọt vào kết quả", r.Domain)
		}
	}
	if len(st.PublicSuffixSamples) == 0 {
		t.Error("không giữ mẫu nào để người vận hành duyệt")
	}
}

// Nhiều rule public suffix nghĩa là feed hỏng hoặc bị can thiệp, không phải chủ ý.
func TestTooManyPublicSuffixesFailsImport(t *testing.T) {
	src := Source{MaxPublicSuffix: 2}

	if err := Validate(src, Stats{Accepted: 100, PublicSuffix: 2}, 0); err != nil {
		t.Errorf("Validate = %v, muốn nil ở đúng ngưỡng", err)
	}
	err := Validate(src, Stats{
		Accepted: 100, PublicSuffix: 3,
		PublicSuffixSamples: []string{"5g.in", "co.uk", "com.au"},
	}, 0)
	if !errors.Is(err, ErrTooManyBroad) {
		t.Errorf("Validate = %v, muốn ErrTooManyBroad", err)
	}
}

func TestParseRejectsNonLineContent(t *testing.T) {
	t.Run("nhị phân", func(t *testing.T) {
		_, _, err := collect(t, "evil.example.com\n\x00\x01\x02\n")
		if !errors.Is(err, ErrNotLineOriented) {
			t.Errorf("Parse = %v, muốn ErrNotLineOriented", err)
		}
	})

	t.Run("dòng quá dài", func(t *testing.T) {
		// Trang HTML lỗi trả về 200 thường là một dòng khổng lồ.
		_, _, err := collect(t, strings.Repeat("a", maxLineBytes+10))
		if !errors.Is(err, ErrNotLineOriented) {
			t.Errorf("Parse = %v, muốn ErrNotLineOriented", err)
		}
	})
}

func TestValidate(t *testing.T) {
	src := Source{MaxRejectRatio: 0.05, MaxChangeRatio: 0.5}

	tests := []struct {
		name     string
		st       Stats
		previous int
		wantErr  error
	}{
		{
			name:    "feed rỗng",
			st:      Stats{Lines: 100, Skipped: 100},
			wantErr: ErrEmptyFeed,
		},
		{
			name:    "quá nhiều dòng lỗi",
			st:      Stats{Accepted: 90, Rejected: 10},
			wantErr: ErrTooManyRejects,
		},
		{
			name:     "teo quá nhiều so với lần trước",
			st:       Stats{Accepted: 100},
			previous: 1000,
			wantErr:  ErrChangeTooLarge,
		},
		{
			name:     "phình quá nhiều so với lần trước",
			st:       Stats{Accepted: 10000},
			previous: 1000,
			wantErr:  ErrChangeTooLarge,
		},
		{
			name:     "tăng trưởng bình thường thì chấp nhận",
			st:       Stats{Accepted: 1100},
			previous: 1000,
			wantErr:  nil,
		},
		{
			name:    "lần import đầu tiên không có mốc so sánh",
			st:      Stats{Accepted: 1000000},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(src, tt.st, tt.previous)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("Validate = %v, muốn nil", err)
				}
				return
			}
			if !errors.Is(err, tt.wantErr) {
				t.Errorf("Validate = %v, muốn %v", err, tt.wantErr)
			}
		})
	}
}

func TestTopRejectReasonsIsStable(t *testing.T) {
	st := Stats{RejectReasons: map[string]int{"is_ip": 5, "invalid_hostname": 5, "unknown": 1}}

	// Duyệt map trong Go có thứ tự ngẫu nhiên; đầu ra vẫn phải ổn định để audit import
	// không đổi nội dung giữa các lần chạy trên cùng dữ liệu.
	first := strings.Join(st.TopRejectReasons(3), " ")
	for range 20 {
		if got := strings.Join(st.TopRejectReasons(3), " "); got != first {
			t.Fatalf("thứ tự không ổn định: %q vs %q", got, first)
		}
	}
	if !strings.HasPrefix(first, "invalid_hostname=5 is_ip=5") {
		t.Errorf("TopRejectReasons = %q, muốn phá hòa theo thứ tự chữ cái", first)
	}
}

// Ngưỡng tỉ lệ không được kích hoạt trên mẫu nhỏ: một feed CERT 50 domain tăng lên 100
// là chuyện bình thường, và một dòng lỗi trong feed 5 dòng không phải bằng chứng feed
// hỏng. Cảnh báo giả làm xói mòn lòng tin vào hàng rào nhanh hơn là không có hàng rào.
func TestRatioGuardsNeedEnoughSamples(t *testing.T) {
	src := Source{MaxRejectRatio: 0.05, MaxChangeRatio: 0.5, MinSampleForRatios: 100}

	t.Run("tỉ lệ lỗi bỏ qua khi mẫu nhỏ", func(t *testing.T) {
		// 1 lỗi trên 5 dòng = 20%, vượt xa ngưỡng 5% — nhưng mẫu quá nhỏ.
		if err := Validate(src, Stats{Accepted: 4, Rejected: 1}, 0); err != nil {
			t.Errorf("Validate = %v, muốn nil trên mẫu nhỏ", err)
		}
	})

	t.Run("tỉ lệ lỗi vẫn áp dụng khi mẫu đủ lớn", func(t *testing.T) {
		if err := Validate(src, Stats{Accepted: 90, Rejected: 10}, 0); !errors.Is(err, ErrTooManyRejects) {
			t.Errorf("Validate = %v, muốn ErrTooManyRejects", err)
		}
	})

	t.Run("biến động bỏ qua khi nền trước nhỏ", func(t *testing.T) {
		// 1 -> 2 là tăng 100%, nhưng trên nền 1 bản ghi thì con số đó vô nghĩa.
		if err := Validate(src, Stats{Accepted: 2}, 1); err != nil {
			t.Errorf("Validate = %v, muốn nil khi nền trước nhỏ", err)
		}
	})

	t.Run("biến động vẫn áp dụng khi nền trước đủ lớn", func(t *testing.T) {
		if err := Validate(src, Stats{Accepted: 100}, 1000); !errors.Is(err, ErrChangeTooLarge) {
			t.Errorf("Validate = %v, muốn ErrChangeTooLarge", err)
		}
	})

	t.Run("feed rỗng vẫn luôn bị từ chối bất kể quy mô", func(t *testing.T) {
		// Đây là hàng rào KHÔNG có ngưỡng mẫu: feed rỗng luôn là lỗi.
		if err := Validate(src, Stats{Lines: 3, Skipped: 3}, 0); !errors.Is(err, ErrEmptyFeed) {
			t.Errorf("Validate = %v, muốn ErrEmptyFeed", err)
		}
	})
}
