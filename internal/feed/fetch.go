// Package feed tải, phân tích và kiểm tra tính toàn vẹn của các nguồn blocklist.
//
// Nguyên tắc bao trùm, lấy từ SKILL.md: một feed hỏng hoặc tải dở PHẢI làm hỏng cả lần
// import và giữ nguyên snapshot cũ. Không bao giờ được lặng lẽ biến lỗi parser thành
// domain bị chặn, và cũng không được biến một feed tải thiếu thành đợt gỡ chặn hàng
// loạt. Mọi kiểm tra trong package này đều nghiêng về phía "từ chối cả lần import".
package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

// Source là cấu hình một nguồn feed.
type Source struct {
	ID   string
	Name string
	URL  string

	// MaxResponseBytes chặn một nguồn bị chiếm quyền đẩy sang phản hồi khổng lồ.
	MaxResponseBytes int64
	Timeout          time.Duration
	MaxAttempts      int

	// MaxChangeRatio: tỉ lệ biến động số dòng tối đa so với lần import trước. Vượt
	// ngưỡng thì dừng chờ duyệt thay vì tự áp dụng.
	MaxChangeRatio float64

	// MaxRejectRatio: tỉ lệ dòng không parse được tối đa.
	MaxRejectRatio float64

	// MinSampleForRatios là số bản ghi tối thiểu để hai ngưỡng TỈ LỆ ở trên có hiệu
	// lực.
	//
	// Tỉ lệ trên mẫu nhỏ là vô nghĩa: một feed CERT 50 domain tăng lên 100 là chuyện
	// bình thường, nhưng ratio báo "biến động 100%". Hai hàng rào kia sinh ra để bắt
	// "feed mất 80% nội dung" hoặc "feed phình 10 lần" — những thứ chỉ có ý nghĩa ở
	// quy mô lớn. Dưới ngưỡng này thì bỏ qua chúng, vì cảnh báo giả làm xói mòn lòng
	// tin vào hàng rào nhanh hơn là không có hàng rào.
	MinSampleForRatios int
}

func (s Source) withDefaults() Source {
	if s.MaxResponseBytes <= 0 {
		s.MaxResponseBytes = 1 << 30 // 1 GiB
	}
	if s.Timeout <= 0 {
		s.Timeout = 5 * time.Minute
	}
	if s.MaxAttempts <= 0 {
		s.MaxAttempts = 3
	}
	if s.MaxChangeRatio <= 0 {
		s.MaxChangeRatio = 0.5
	}
	if s.MaxRejectRatio <= 0 {
		s.MaxRejectRatio = 0.05
	}
	if s.MinSampleForRatios <= 0 {
		s.MinSampleForRatios = 100
	}
	return s
}

// Conditional là trạng thái cache của lần import trước.
type Conditional struct {
	ETag         string
	LastModified string
}

// Errors phân biệt được để bên gọi ghi đúng lý do vào audit import.
var (
	ErrNotModified  = errors.New("feed không đổi")
	ErrTooLarge     = errors.New("phản hồi vượt kích thước tối đa")
	ErrTruncated    = errors.New("phản hồi bị cắt cụt")
	ErrBadStatus    = errors.New("mã trạng thái HTTP không chấp nhận được")
	ErrTooManyTries = errors.New("hết số lần thử")
)

// Fetcher tải nội dung feed.
type Fetcher struct {
	Client *http.Client
	// Sleep cho phép test chạy nhanh; nil thì dùng time.Sleep.
	Sleep func(time.Duration)
	// Jitter trả về hệ số nhiễu trong [0,1); nil thì dùng rand.
	Jitter func() float64
	// UserAgent tự giới thiệu để phía nguồn liên hệ được khi có vấn đề.
	UserAgent string
}

// NewFetcher dựng Fetcher với thiết lập mặc định hợp lý.
func NewFetcher() *Fetcher {
	return &Fetcher{
		Client: &http.Client{
			// Không đặt Timeout ở đây: giới hạn theo từng lần tải nằm ở context, để
			// một feed 200 MB chậm không bị cắt ngang oan.
			Transport: http.DefaultTransport.(*http.Transport).Clone(),
		},
		UserAgent: "CyberDNS-TIP/1.0 (+https://tip.cyberdns.vn)",
	}
}

// Response là một lần tải thành công. Body phải được đọc hết rồi đóng; Hash và Bytes
// chỉ đúng sau khi đã đọc xong.
type Response struct {
	Status       int
	ETag         string
	LastModified string
	Body         io.ReadCloser

	counter *countingReader
}

// Hash trả về SHA-256 của nội dung đã đọc.
func (r *Response) Hash() string {
	return "sha256:" + hex.EncodeToString(r.counter.hash.Sum(nil))
}

// Bytes trả về số byte đã đọc.
func (r *Response) Bytes() int64 { return r.counter.n }

// Fetch tải feed, dùng request có điều kiện khi có sẵn trạng thái cache.
//
// Trả về ErrNotModified khi phía nguồn đáp 304 — khi đó không có gì để làm và cũng
// không nên dựng lại snapshot.
func (f *Fetcher) Fetch(ctx context.Context, src Source, cond Conditional) (*Response, error) {
	src = src.withDefaults()

	var lastErr error
	for attempt := 1; attempt <= src.MaxAttempts; attempt++ {
		if attempt > 1 {
			if err := f.backoff(ctx, attempt); err != nil {
				return nil, err
			}
		}

		resp, err := f.attempt(ctx, src, cond)
		switch {
		case err == nil:
			return resp, nil
		case errors.Is(err, ErrNotModified):
			return nil, err
		case !retryable(err):
			return nil, err
		}
		lastErr = err
	}

	return nil, fmt.Errorf("%w sau %d lần: %w", ErrTooManyTries, src.MaxAttempts, lastErr)
}

func (f *Fetcher) attempt(ctx context.Context, src Source, cond Conditional) (*Response, error) {
	ctx, cancel := context.WithTimeout(ctx, src.Timeout)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("dựng request: %w", err)
	}
	req.Header.Set("User-Agent", f.UserAgent)
	// KHÔNG tự đặt Accept-Encoding: đặt tay sẽ tắt cơ chế giải nén tự động của Go và
	// parser sẽ nhận về dữ liệu nén. Để mặc định thì transport tự thêm gzip và tự giải
	// nén; đổi lại ContentLength thành -1 nên phép kiểm tra cắt cụt bên dưới bị bỏ qua
	// với phản hồi nén — chấp nhận được, vì bản thân gzip có CRC và một luồng gzip đứt
	// giữa chừng sẽ báo lỗi ngay lúc đọc.
	if cond.ETag != "" {
		req.Header.Set("If-None-Match", cond.ETag)
	}
	if cond.LastModified != "" {
		req.Header.Set("If-Modified-Since", cond.LastModified)
	}

	httpResp, err := f.client().Do(req)
	if err != nil {
		cancel()
		return nil, &transportError{err}
	}

	if httpResp.StatusCode == http.StatusNotModified {
		httpResp.Body.Close()
		cancel()
		return nil, ErrNotModified
	}
	if httpResp.StatusCode != http.StatusOK {
		httpResp.Body.Close()
		cancel()
		return nil, &statusError{code: httpResp.StatusCode}
	}

	// Content-Length lớn hơn trần thì hỏng ngay, không tải về rồi mới bỏ.
	if httpResp.ContentLength > src.MaxResponseBytes {
		httpResp.Body.Close()
		cancel()
		return nil, fmt.Errorf("%w: Content-Length %d > %d",
			ErrTooLarge, httpResp.ContentLength, src.MaxResponseBytes)
	}

	counter := &countingReader{
		r:        httpResp.Body,
		hash:     sha256.New(),
		limit:    src.MaxResponseBytes,
		expected: httpResp.ContentLength,
	}

	return &Response{
		Status:       httpResp.StatusCode,
		ETag:         httpResp.Header.Get("ETag"),
		LastModified: httpResp.Header.Get("Last-Modified"),
		Body: &bodyCloser{
			Reader: counter,
			closers: []func() error{
				httpResp.Body.Close,
				func() error { cancel(); return nil },
			},
			onClose: counter.checkComplete,
		},
		counter: counter,
	}, nil
}

func (f *Fetcher) client() *http.Client {
	if f.Client != nil {
		return f.Client
	}
	return http.DefaultClient
}

// backoff chờ theo hàm mũ có nhiễu. Nhiễu tránh việc nhiều nguồn cùng thử lại đồng loạt.
func (f *Fetcher) backoff(ctx context.Context, attempt int) error {
	base := time.Duration(1<<uint(attempt-1)) * time.Second
	jitter := f.jitter()
	d := base + time.Duration(float64(base)*jitter)

	if f.Sleep != nil {
		f.Sleep(d)
		return ctx.Err()
	}

	select {
	case <-time.After(d):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (f *Fetcher) jitter() float64 {
	if f.Jitter != nil {
		return f.Jitter()
	}
	return rand.Float64()
}

// countingReader đếm byte, băm nội dung và chặn khi vượt trần.
type countingReader struct {
	r        io.Reader
	hash     hash.Hash
	limit    int64
	expected int64 // Content-Length, -1 nếu không biết
	n        int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, fmt.Errorf("%w: đã đọc %d byte", ErrTooLarge, c.n)
	}
	if int64(len(p)) > c.limit-c.n {
		p = p[:c.limit-c.n]
	}

	n, err := c.r.Read(p)
	if n > 0 {
		c.n += int64(n)
		c.hash.Write(p[:n])
	}
	return n, err
}

// checkComplete phát hiện phản hồi bị cắt cụt.
//
// Đây là điểm chặn quan trọng: một feed tải được một nửa trông y hệt một feed đã gỡ bỏ
// một nửa số domain. Không kiểm tra thì mỗi lần mạng chập chờn sẽ thành một đợt gỡ chặn
// hàng loạt.
func (c *countingReader) checkComplete() error {
	if c.expected >= 0 && c.n != c.expected {
		return fmt.Errorf("%w: đọc được %d byte, Content-Length báo %d",
			ErrTruncated, c.n, c.expected)
	}
	return nil
}

// bodyCloser gộp nhiều hàm dọn dẹp và chạy kiểm tra toàn vẹn lúc đóng.
type bodyCloser struct {
	io.Reader
	closers []func() error
	onClose func() error
}

func (b *bodyCloser) Close() error {
	err := b.onClose()
	for _, c := range b.closers {
		if cerr := c(); cerr != nil && err == nil {
			err = cerr
		}
	}
	return err
}

type transportError struct{ err error }

func (e *transportError) Error() string { return "lỗi truyền tải: " + e.err.Error() }
func (e *transportError) Unwrap() error { return e.err }

type statusError struct{ code int }

func (e *statusError) Error() string {
	return fmt.Sprintf("%v: %d", ErrBadStatus, e.code)
}
func (e *statusError) Is(target error) bool { return target == ErrBadStatus }

// retryable phân biệt lỗi tạm thời với lỗi vĩnh viễn.
//
// Thử lại 4xx là vô ích và chỉ làm phiền phía nguồn; 5xx, 429 và lỗi mạng thì đáng thử.
func retryable(err error) bool {
	var te *transportError
	if errors.As(err, &te) {
		return true
	}

	var se *statusError
	if errors.As(err, &se) {
		return se.code == http.StatusTooManyRequests || se.code >= 500
	}
	return false
}
