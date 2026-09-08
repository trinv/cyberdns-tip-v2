package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Loại yêu cầu "chạy ngay" mà dashboard có thể đặt.
const (
	TriggerSync   = "sync"
	TriggerPolicy = "policy"
	TriggerBuild  = "build"
)

// Trạng thái của một yêu cầu.
const (
	TriggerPending = "pending"
	TriggerRunning = "running"
	TriggerDone    = "done"
	TriggerFailed  = "failed"
)

// Trigger là một yêu cầu "chạy ngay" từ dashboard, xem migration 0008.
type Trigger struct {
	ID          int64
	Kind        string
	SourceID    *int64
	SourceName  string
	Status      string
	RequestedBy string
	RequestedAt time.Time
	ClaimedAt   *time.Time
	CompletedAt *time.Time
	// Result là JSON thô — store không biết và không cần biết hình dạng bên trong.
	Result       string
	ErrorMessage string
}

// ErrTriggerNotFound báo không có yêu cầu nào mang id đó.
var ErrTriggerNotFound = errors.New("store: không có yêu cầu này")

// EnqueueTrigger đặt một yêu cầu chạy ngay, trả về id và việc nó có MỚI được tạo hay
// không.
//
// Không tạo yêu cầu trùng: nếu đã có một yêu cầu CÙNG loại và CÙNG nguồn đang chờ hoặc
// đang chạy, trả về id của yêu cầu đó. Thiếu bước này, bấm nút vài lần liền trong lúc
// service đang bận sẽ dồn một hàng yêu cầu giống hệt nhau.
func (s *Store) EnqueueTrigger(ctx context.Context, kind string, sourceID *int64, requestedBy string) (id int64, created bool, err error) {
	// Dọn rác cơ hội: xóa các yêu cầu đã xong quá lâu. Bảng này nhỏ và không cần một
	// job riêng chỉ để dọn nó — làm tiện thể mỗi lần có yêu cầu mới là đủ.
	if _, err := s.pool.Exec(ctx, `
		DELETE FROM admin_triggers
		 WHERE status IN ('done', 'failed') AND completed_at < NOW() - INTERVAL '7 days'`,
	); err != nil {
		return 0, false, fmt.Errorf("store: dọn yêu cầu cũ: %w", err)
	}

	err = s.pool.QueryRow(ctx, `
		SELECT id FROM admin_triggers
		 WHERE kind = $1::trigger_kind AND status IN ('pending', 'running')
		   AND source_id IS NOT DISTINCT FROM $2::bigint
		 ORDER BY id LIMIT 1`, kind, sourceID).Scan(&id)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return 0, false, fmt.Errorf("store: kiểm tra yêu cầu đang chờ: %w", err)
	}

	err = s.pool.QueryRow(ctx, `
		INSERT INTO admin_triggers (kind, source_id, requested_by)
		VALUES ($1::trigger_kind, $2::bigint, $3)
		RETURNING id`, kind, sourceID, requestedBy).Scan(&id)
	if err != nil {
		return 0, false, fmt.Errorf("store: tạo yêu cầu: %w", err)
	}
	return id, true, nil
}

// ClaimTrigger lấy MỘT yêu cầu đang chờ của kind này để xử lý, nếu có.
//
// FOR UPDATE SKIP LOCKED trong truy vấn con: an toàn nếu có nhiều hơn một instance của
// cùng service cùng poll bảng này (dù hiện tại luôn chỉ có một), và không bao giờ có
// hai bên chờ khóa lẫn nhau.
func (s *Store) ClaimTrigger(ctx context.Context, kind string) (Trigger, bool, error) {
	var t Trigger
	err := s.pool.QueryRow(ctx, `
		UPDATE admin_triggers
		   SET status = 'running', claimed_at = NOW()
		 WHERE id = (
		   SELECT id FROM admin_triggers
		    WHERE kind = $1::trigger_kind AND status = 'pending'
		    ORDER BY id
		    LIMIT 1
		    FOR UPDATE SKIP LOCKED
		 )
		RETURNING id, kind::text, source_id, requested_by, requested_at`,
		kind).Scan(&t.ID, &t.Kind, &t.SourceID, &t.RequestedBy, &t.RequestedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Trigger{}, false, nil
	}
	if err != nil {
		return Trigger{}, false, fmt.Errorf("store: nhận yêu cầu: %w", err)
	}
	return t, true, nil
}

// FinishTrigger đóng một yêu cầu đã claim, kèm kết quả hoặc lý do lỗi.
//
// status phải là "done" hoặc "failed". result là JSON thô, rỗng nếu không có gì đáng
// lưu lại.
func (s *Store) FinishTrigger(ctx context.Context, id int64, status, result, errMsg string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE admin_triggers
		   SET status = $2::trigger_status,
		       completed_at = NOW(),
		       result = NULLIF($3, '')::jsonb,
		       error_message = NULLIF($4, '')
		 WHERE id = $1::bigint`,
		id, status, result, errMsg)
	if err != nil {
		return fmt.Errorf("store: đóng yêu cầu: %w", err)
	}
	return nil
}

// TriggerStatus đọc một yêu cầu để dashboard hỏi thăm tiến độ.
func (s *Store) TriggerStatus(ctx context.Context, id int64) (Trigger, error) {
	var (
		t          Trigger
		sourceName *string
		result     *string
		errMsg     *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.kind::text, t.source_id, src.name,
		       t.status::text, t.requested_by, t.requested_at,
		       t.claimed_at, t.completed_at, t.result::text, t.error_message
		  FROM admin_triggers t
		  LEFT JOIN sources src ON src.id = t.source_id
		 WHERE t.id = $1::bigint`, id).
		Scan(&t.ID, &t.Kind, &t.SourceID, &sourceName,
			&t.Status, &t.RequestedBy, &t.RequestedAt,
			&t.ClaimedAt, &t.CompletedAt, &result, &errMsg)
	if errors.Is(err, pgx.ErrNoRows) {
		return Trigger{}, ErrTriggerNotFound
	}
	if err != nil {
		return Trigger{}, fmt.Errorf("store: đọc yêu cầu: %w", err)
	}
	if sourceName != nil {
		t.SourceName = *sourceName
	}
	if result != nil {
		t.Result = *result
	}
	if errMsg != nil {
		t.ErrorMessage = *errMsg
	}
	return t, nil
}
