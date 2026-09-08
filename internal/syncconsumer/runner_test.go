package syncconsumer

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/opencti"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// fakeOpenCTI là một máy chủ SSE tối giản, đủ để kiểm chứng hành vi nối lại.
type fakeOpenCTI struct {
	mu sync.Mutex
	// startFroms ghi lại header Last-Event-ID của từng lần kết nối. Đây là bằng chứng
	// then chốt: nối lại mà không mang theo id sẽ mất một khoảng dữ liệu mỗi lần đứt.
	startFroms []string
	conns      int
}

func (f *fakeOpenCTI) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.conns++
		n := f.conns
		f.startFroms = append(f.startFroms, r.Header.Get("Last-Event-ID"))
		f.mu.Unlock()

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		// Mỗi lần kết nối phát một sự kiện rồi đóng, mô phỏng kết nối bị đứt.
		fmt.Fprintf(w, "event: create\nid: evt-%d\n", n)
		fmt.Fprintf(w, `data: {"data":{"type":"domain-name","id":"domain-name--%d","value":"d%d.example.com"}}`, n, n)
		fmt.Fprint(w, "\n\n")
	}
}

func (f *fakeOpenCTI) snapshot() (int, []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.conns, append([]string(nil), f.startFroms...)
}

func TestRunReconnectsAndResumes(t *testing.T) {
	fake := &fakeOpenCTI{}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	f := &fakeStore{}
	c := New(f, Options{
		Source:          store.Source{ID: 7, Name: "opencti"},
		StreamID:        "live-test",
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		CheckpointEvery: 1000,
		CheckpointAfter: time.Hour,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- c.Run(ctx, RunOptions{
			Stream: opencti.StreamConfig{
				URL:          srv.URL + "/stream/live-test",
				Token:        "t",
				ListenDelete: true,
				HTTPClient:   srv.Client(),
			},
			MinBackoff: 10 * time.Millisecond,
			MaxBackoff: 50 * time.Millisecond,
		})
	}()

	// Chờ vài vòng nối lại.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if n, _ := fake.snapshot(); n >= 3 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	if err := <-done; err != nil {
		t.Fatalf("Run: %v", err)
	}

	conns, starts := fake.snapshot()
	if conns < 3 {
		t.Fatalf("số lần kết nối = %d, muốn >= 3", conns)
	}
	if starts[0] != "" {
		t.Errorf("lần kết nối đầu mang Last-Event-ID = %q, muốn rỗng", starts[0])
	}
	// Từ lần thứ hai trở đi phải nối lại từ sự kiện cuối đã xử lý.
	for i := 1; i < len(starts) && i < 3; i++ {
		want := fmt.Sprintf("evt-%d", i)
		if starts[i] != want {
			t.Errorf("lần kết nối %d bắt đầu từ %q, muốn %q", i+1, starts[i], want)
		}
	}
}

// Đóng kết nối phải ghi checkpoint ngay, không chờ đủ lô. Chờ đủ lô thì mọi sự kiện dở
// dang sẽ bị xử lý lại sau mỗi lần đứt kết nối.
func TestRunFlushesOnDisconnect(t *testing.T) {
	fake := &fakeOpenCTI{}
	srv := httptest.NewServer(fake.handler(t))
	defer srv.Close()

	f := &fakeStore{}
	c := New(f, Options{
		Source:          store.Source{ID: 7},
		StreamID:        "live-test",
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
		CheckpointEvery: 1000,
		CheckpointAfter: time.Hour,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	_ = c.Run(ctx, RunOptions{
		Stream: opencti.StreamConfig{
			URL:        srv.URL + "/stream/live-test",
			HTTPClient: srv.Client(),
		},
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 20 * time.Millisecond,
	})

	if len(f.saves) == 0 {
		t.Fatal("không ghi checkpoint nào khi kết nối đóng")
	}
}

// Server từ chối liên tục: vòng lặp phải kiên trì thay vì thoát, và phải dừng gọn khi
// ctx bị hủy.
func TestRunSurvivesPersistentFailure(t *testing.T) {
	var attempts int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		attempts++
		mu.Unlock()
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	f := &fakeStore{}
	c := New(f, Options{
		Source:   store.Source{ID: 7},
		StreamID: "live-test",
		Log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()

	if err := c.Run(ctx, RunOptions{
		Stream:     opencti.StreamConfig{URL: srv.URL, HTTPClient: srv.Client()},
		MinBackoff: 10 * time.Millisecond,
		MaxBackoff: 30 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Run = %v, muốn nil khi ctx hết hạn", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if attempts < 2 {
		t.Errorf("số lần thử = %d, muốn >= 2", attempts)
	}
}

func TestJitterStaysInRange(t *testing.T) {
	base := time.Second
	for i := 0; i < 200; i++ {
		got := jitter(base)
		if got < 750*time.Millisecond || got > 1250*time.Millisecond {
			t.Fatalf("jitter = %v, ngoài phạm vi ±25%%", got)
		}
	}
	if jitter(0) != 0 {
		t.Error("jitter(0) phải bằng 0")
	}
}
