package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"

	"github.com/vnnic/cyberdns-tip/internal/store"
)

func TestEnqueueTriggerCreatesPendingRow(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	id, created, err := s.EnqueueTrigger(ctx, store.TriggerBuild, nil, "admin@vnnic.vn")
	if err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}
	if !created {
		t.Error("created = false ở lần đầu, muốn true")
	}
	if id == 0 {
		t.Error("id = 0")
	}

	got, err := s.TriggerStatus(ctx, id)
	if err != nil {
		t.Fatalf("TriggerStatus: %v", err)
	}
	if got.Status != store.TriggerPending {
		t.Errorf("Status = %q, muốn %q", got.Status, store.TriggerPending)
	}
	if got.RequestedBy != "admin@vnnic.vn" {
		t.Errorf("RequestedBy = %q", got.RequestedBy)
	}
}

// Bấm nút vài lần liền trong lúc service đang bận không được dồn thêm yêu cầu: hai lần
// gọi liên tiếp cùng loại, cùng nguồn phải trả về CÙNG một id.
func TestEnqueueTriggerDedupsPending(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	id1, created1, err := s.EnqueueTrigger(ctx, store.TriggerPolicy, nil, "a@vnnic.vn")
	if err != nil {
		t.Fatalf("lần 1: %v", err)
	}
	if !created1 {
		t.Fatal("lần 1: created = false")
	}

	id2, created2, err := s.EnqueueTrigger(ctx, store.TriggerPolicy, nil, "b@vnnic.vn")
	if err != nil {
		t.Fatalf("lần 2: %v", err)
	}
	if created2 {
		t.Error("lần 2: created = true, muốn dùng lại yêu cầu đang chờ")
	}
	if id1 != id2 {
		t.Errorf("id1=%d id2=%d, muốn giống nhau", id1, id2)
	}
}

// Hai yêu cầu "sync" khác NGUỒN không được coi là trùng nhau, dù cùng loại.
func TestEnqueueTriggerDoesNotDedupDifferentSources(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	a := addSource(t, pool, "t-trig-a", `["malware"]`, 604800)
	b := addSource(t, pool, "t-trig-b", `["malware"]`, 604800)

	id1, _, err := s.EnqueueTrigger(ctx, store.TriggerSync, &a.ID, "x@vnnic.vn")
	if err != nil {
		t.Fatalf("nguồn a: %v", err)
	}
	id2, created2, err := s.EnqueueTrigger(ctx, store.TriggerSync, &b.ID, "x@vnnic.vn")
	if err != nil {
		t.Fatalf("nguồn b: %v", err)
	}
	if !created2 {
		t.Error("nguồn b bị coi là trùng với nguồn a")
	}
	if id1 == id2 {
		t.Error("hai nguồn khác nhau lại chung một id yêu cầu")
	}

	// Và yêu cầu "mọi nguồn" (source_id NULL) cũng không trùng với yêu cầu của một
	// nguồn cụ thể.
	idAll, createdAll, err := s.EnqueueTrigger(ctx, store.TriggerSync, nil, "x@vnnic.vn")
	if err != nil {
		t.Fatalf("mọi nguồn: %v", err)
	}
	if !createdAll || idAll == id1 || idAll == id2 {
		t.Error("yêu cầu 'mọi nguồn' bị trộn lẫn với yêu cầu của một nguồn cụ thể")
	}
}

func TestClaimTriggerMovesToRunning(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	id, _, err := s.EnqueueTrigger(ctx, store.TriggerSync, nil, "a@vnnic.vn")
	if err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}

	claimed, ok, err := s.ClaimTrigger(ctx, store.TriggerSync)
	if err != nil {
		t.Fatalf("ClaimTrigger: %v", err)
	}
	if !ok {
		t.Fatal("ClaimTrigger: ok = false, muốn true")
	}
	if claimed.ID != id {
		t.Errorf("claimed.ID = %d, muốn %d", claimed.ID, id)
	}

	got, err := s.TriggerStatus(ctx, id)
	if err != nil {
		t.Fatalf("TriggerStatus: %v", err)
	}
	if got.Status != store.TriggerRunning {
		t.Errorf("Status = %q, muốn %q", got.Status, store.TriggerRunning)
	}
	if got.ClaimedAt == nil {
		t.Error("ClaimedAt rỗng sau khi claim")
	}
}

// Không có yêu cầu nào đang chờ: ClaimTrigger phải trả ok=false, không phải lỗi.
func TestClaimTriggerEmptyQueue(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	_, ok, err := s.ClaimTrigger(ctx, store.TriggerSync)
	if err != nil {
		t.Fatalf("ClaimTrigger: %v", err)
	}
	if ok {
		t.Error("ok = true dù hàng đợi rỗng")
	}
}

// Đúng loại mới được nhận: một yêu cầu 'build' đang chờ không được ClaimTrigger('sync')
// nhặt nhầm.
func TestClaimTriggerFiltersByKind(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if _, _, err := s.EnqueueTrigger(ctx, store.TriggerBuild, nil, "a@vnnic.vn"); err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}

	_, ok, err := s.ClaimTrigger(ctx, store.TriggerSync)
	if err != nil {
		t.Fatalf("ClaimTrigger: %v", err)
	}
	if ok {
		t.Error("ClaimTrigger('sync') nhặt nhầm yêu cầu 'build'")
	}
}

// FOR UPDATE SKIP LOCKED: hai lần claim đồng thời cho CÙNG một yêu cầu đang chờ không
// bao giờ được cả hai cùng thành công — nếu không, service sẽ chạy trùng lặp cùng một
// việc, đúng thứ mà cơ chế trigger tồn tại để tránh.
func TestClaimTriggerIsExclusive(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	if _, _, err := s.EnqueueTrigger(ctx, store.TriggerBuild, nil, "a@vnnic.vn"); err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}

	const attempts = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	claimedCount := 0

	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.ClaimTrigger(ctx, store.TriggerBuild)
			if err != nil {
				t.Errorf("ClaimTrigger: %v", err)
				return
			}
			if ok {
				mu.Lock()
				claimedCount++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if claimedCount != 1 {
		t.Errorf("số lần claim thành công = %d, muốn đúng 1", claimedCount)
	}
}

func TestFinishTriggerDone(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	id, _, err := s.EnqueueTrigger(ctx, store.TriggerBuild, nil, "a@vnnic.vn")
	if err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}
	if _, _, err := s.ClaimTrigger(ctx, store.TriggerBuild); err != nil {
		t.Fatalf("ClaimTrigger: %v", err)
	}

	if err := s.FinishTrigger(ctx, id, store.TriggerDone, `{"Entries":123}`, ""); err != nil {
		t.Fatalf("FinishTrigger: %v", err)
	}

	got, err := s.TriggerStatus(ctx, id)
	if err != nil {
		t.Fatalf("TriggerStatus: %v", err)
	}
	if got.Status != store.TriggerDone {
		t.Errorf("Status = %q, muốn %q", got.Status, store.TriggerDone)
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt rỗng")
	}
	// So theo ngữ nghĩa JSON, không so chuỗi thô: PostgreSQL chuẩn hóa lại khoảng
	// trắng khi ép kiểu jsonb rồi đọc lại dưới dạng text.
	var parsed struct{ Entries int }
	if err := json.Unmarshal([]byte(got.Result), &parsed); err != nil {
		t.Fatalf("Result không phải JSON hợp lệ: %q: %v", got.Result, err)
	}
	if parsed.Entries != 123 {
		t.Errorf("Result.Entries = %d, muốn 123", parsed.Entries)
	}
	if got.ErrorMessage != "" {
		t.Errorf("ErrorMessage = %q, muốn rỗng", got.ErrorMessage)
	}
}

func TestFinishTriggerFailed(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	id, _, err := s.EnqueueTrigger(ctx, store.TriggerSync, nil, "a@vnnic.vn")
	if err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}

	if err := s.FinishTrigger(ctx, id, store.TriggerFailed, "", "tải feed thất bại: 503"); err != nil {
		t.Fatalf("FinishTrigger: %v", err)
	}

	got, err := s.TriggerStatus(ctx, id)
	if err != nil {
		t.Fatalf("TriggerStatus: %v", err)
	}
	if got.Status != store.TriggerFailed {
		t.Errorf("Status = %q, muốn %q", got.Status, store.TriggerFailed)
	}
	if got.ErrorMessage != "tải feed thất bại: 503" {
		t.Errorf("ErrorMessage = %q", got.ErrorMessage)
	}
	if got.Result != "" {
		t.Errorf("Result = %q, muốn rỗng", got.Result)
	}
}

func TestTriggerStatusIncludesSourceName(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	src := addSource(t, pool, "t-trig-name", `["malware"]`, 604800)
	id, _, err := s.EnqueueTrigger(ctx, store.TriggerSync, &src.ID, "a@vnnic.vn")
	if err != nil {
		t.Fatalf("EnqueueTrigger: %v", err)
	}

	got, err := s.TriggerStatus(ctx, id)
	if err != nil {
		t.Fatalf("TriggerStatus: %v", err)
	}
	if got.SourceID == nil || *got.SourceID != src.ID {
		t.Errorf("SourceID = %v, muốn %d", got.SourceID, src.ID)
	}
	if got.SourceName != "t-trig-name" {
		t.Errorf("SourceName = %q, muốn t-trig-name", got.SourceName)
	}
}

func TestTriggerStatusNotFound(t *testing.T) {
	s, _ := newStore(t)
	ctx := context.Background()

	_, err := s.TriggerStatus(ctx, 999999)
	if !errors.Is(err, store.ErrTriggerNotFound) {
		t.Fatalf("lỗi = %v, muốn %v", err, store.ErrTriggerNotFound)
	}
}
