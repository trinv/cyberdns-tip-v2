package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/metrics"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// fakeTriggerStore mô phỏng bảng admin_triggers trong bộ nhớ, đủ để kiểm chứng phần
// điều phối của RunLoopWithTrigger mà không cần PostgreSQL.
type fakeTriggerStore struct {
	mu       sync.Mutex
	pending  []store.Trigger
	finished []finishCall
}

type finishCall struct {
	id     int64
	status string
	result string
	errMsg string
}

func (f *fakeTriggerStore) enqueue(t store.Trigger) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.pending = append(f.pending, t)
}

func (f *fakeTriggerStore) ClaimTrigger(_ context.Context, kind string) (store.Trigger, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, t := range f.pending {
		if t.Kind == kind {
			f.pending = append(f.pending[:i:i], f.pending[i+1:]...)
			return t, true, nil
		}
	}
	return store.Trigger{}, false, nil
}

func (f *fakeTriggerStore) FinishTrigger(_ context.Context, id int64, status, result, errMsg string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.finished = append(f.finished, finishCall{id, status, result, errMsg})
	return nil
}

func (f *fakeTriggerStore) finishedCalls() []finishCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]finishCall(nil), f.finished...)
}

func testService() *Service {
	return &Service{
		Name:    "test",
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		Metrics: metrics.New("test", "dev"),
	}
}

// Yêu cầu thủ công đang chờ phải được xử lý trước lượt theo lịch, và job phải nhận
// đúng sourceID mang theo trong yêu cầu.
func TestRunLoopWithTriggerConsumesPendingBeforeSchedule(t *testing.T) {
	fs := &fakeTriggerStore{}
	srcID := int64(42)
	fs.enqueue(store.Trigger{ID: 7, Kind: store.TriggerSync, SourceID: &srcID})

	var calls []*int64
	var mu sync.Mutex
	done := make(chan struct{})

	job := func(_ context.Context, _ time.Time, sourceID *int64) (any, error) {
		mu.Lock()
		calls = append(calls, sourceID)
		mu.Unlock()
		close(done)
		return map[string]int{"ok": 1}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go testService().RunLoopWithTrigger(ctx, "t", store.TriggerSync, fs,
		time.Hour, 5*time.Millisecond, false, job)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("job không được gọi trong 2s")
	}
	// close(done) chạy TRONG job, trước khi job trả về; FinishTrigger chỉ được gọi sau
	// khi job đã trả về xong. Đợi thêm một nhịp để không đọc finishedCalls() quá sớm.
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	if len(calls) != 1 {
		t.Fatalf("số lần gọi job = %d, muốn 1", len(calls))
	}
	if calls[0] == nil || *calls[0] != srcID {
		t.Errorf("sourceID = %v, muốn %d", calls[0], srcID)
	}

	finished := fs.finishedCalls()
	if len(finished) != 1 {
		t.Fatalf("số lần FinishTrigger = %d, muốn 1", len(finished))
	}
	if finished[0].id != 7 || finished[0].status != "done" {
		t.Errorf("finish = %+v, muốn id=7 status=done", finished[0])
	}
}

// Không có yêu cầu thủ công nào: lượt theo lịch vẫn phải chạy (runAtStart), và job của
// lượt đó nhận sourceID=nil, không có FinishTrigger nào được gọi (không gắn với yêu
// cầu nào cả).
func TestRunLoopWithTriggerRunsScheduledWhenQueueEmpty(t *testing.T) {
	fs := &fakeTriggerStore{}
	done := make(chan *int64, 1)

	job := func(_ context.Context, _ time.Time, sourceID *int64) (any, error) {
		done <- sourceID
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go testService().RunLoopWithTrigger(ctx, "t", store.TriggerBuild, fs,
		time.Hour, 5*time.Millisecond, true, job)

	select {
	case sourceID := <-done:
		if sourceID != nil {
			t.Errorf("sourceID = %v, muốn nil ở lượt theo lịch", *sourceID)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lượt theo lịch không chạy dù runAtStart=true")
	}

	if len(fs.finishedCalls()) != 0 {
		t.Errorf("FinishTrigger bị gọi cho lượt theo lịch: %v", fs.finishedCalls())
	}
}

// Job lỗi phải đóng yêu cầu với status=failed kèm thông điệp lỗi, để dashboard hiển thị
// được lý do thay vì treo mãi ở "đang chạy".
func TestRunLoopWithTriggerReportsFailure(t *testing.T) {
	fs := &fakeTriggerStore{}
	fs.enqueue(store.Trigger{ID: 9, Kind: store.TriggerPolicy})

	boom := errors.New("mất kết nối CSDL")
	done := make(chan struct{})
	job := func(context.Context, time.Time, *int64) (any, error) {
		defer close(done)
		return nil, boom
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go testService().RunLoopWithTrigger(ctx, "t", store.TriggerPolicy, fs,
		time.Hour, 5*time.Millisecond, false, job)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("job không được gọi")
	}

	// FinishTrigger chạy sau khi job trả lỗi — đợi thêm một nhịp poll để chắc chắn nó
	// đã được gọi trước khi kiểm tra.
	time.Sleep(20 * time.Millisecond)

	finished := fs.finishedCalls()
	if len(finished) != 1 {
		t.Fatalf("số lần FinishTrigger = %d, muốn 1", len(finished))
	}
	if finished[0].status != "failed" {
		t.Errorf("status = %q, muốn failed", finished[0].status)
	}
	if finished[0].errMsg != boom.Error() {
		t.Errorf("errMsg = %q, muốn %q", finished[0].errMsg, boom.Error())
	}
}

// Bất biến quan trọng nhất: dù kích hoạt bằng lượt theo lịch hay yêu cầu thủ công, KHÔNG
// BAO GIỜ có hai lượt job chạy chồng lên nhau. Thiếu bất biến này, một yêu cầu "đồng bộ
// ngay" có thể rơi đúng lúc lượt theo chu kỳ đang xử lý cùng một nguồn.
func TestRunLoopWithTriggerNeverOverlaps(t *testing.T) {
	fs := &fakeTriggerStore{}
	// Xếp sẵn nhiều yêu cầu để job phải chạy liên tục, xen giữa các lượt theo lịch.
	for i := int64(1); i <= 5; i++ {
		fs.enqueue(store.Trigger{ID: i, Kind: store.TriggerSync})
	}

	var running int32
	var overlapped atomic.Bool
	var runs atomic.Int64

	job := func(context.Context, time.Time, *int64) (any, error) {
		if atomic.AddInt32(&running, 1) > 1 {
			overlapped.Store(true)
		}
		time.Sleep(8 * time.Millisecond)
		atomic.AddInt32(&running, -1)
		runs.Add(1)
		return nil, nil
	}

	ctx, cancel := context.WithCancel(context.Background())

	go testService().RunLoopWithTrigger(ctx, "t", store.TriggerSync, fs,
		15*time.Millisecond, 3*time.Millisecond, true, job)

	deadline := time.Now().Add(2 * time.Second)
	for runs.Load() < 8 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	cancel()

	if runs.Load() < 8 {
		t.Fatalf("job chỉ chạy %d lần trong 2s, quá ít để kiểm chứng", runs.Load())
	}
	if overlapped.Load() {
		t.Error("hai lượt job chạy chồng lên nhau")
	}
}

// Vòng lặp phải dừng êm khi ctx bị hủy, không phải chạy mãi.
func TestRunLoopWithTriggerStopsOnCancel(t *testing.T) {
	fs := &fakeTriggerStore{}
	job := func(context.Context, time.Time, *int64) (any, error) { return nil, nil }

	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		testService().RunLoopWithTrigger(ctx, "t", store.TriggerSync, fs,
			time.Hour, 5*time.Millisecond, false, job)
		close(loopDone)
	}()

	cancel()

	select {
	case <-loopDone:
	case <-time.After(2 * time.Second):
		t.Fatal("vòng lặp không dừng sau khi ctx bị hủy")
	}
}
