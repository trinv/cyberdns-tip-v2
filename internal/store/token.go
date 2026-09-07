package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// NewToken sinh một token truy cập mới.
//
// Trả về giá trị thô để đưa cho tenant và hash để lưu. Giá trị thô KHÔNG được lưu:
// nếu CSDL rò rỉ thì token vẫn không dùng lại được.
func NewToken() (raw, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("store: sinh token: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	return raw, HashToken(raw), nil
}

// HashToken băm một token để đối chiếu với cột token_hash.
func HashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// TokenResolver tra token sang slug tenant, có đệm.
//
// Đệm ở đây không phải để tối ưu tốc độ mà là yêu cầu về khả năng chịu lỗi: tra CSDL
// cho MỖI request nghĩa là một sự cố PostgreSQL sẽ làm sập luôn việc phục vụ blocklist,
// phá vỡ nguyên tắc "phục vụ không phụ thuộc control plane" của cả kiến trúc.
//
// Khi CSDL không trả lời, bộ tra phục vụ bằng dữ liệu cũ trong khoảng MaxStale. Đánh
// đổi có chủ ý: một token vừa bị thu hồi có thể còn dùng được thêm tối đa MaxStale, và
// điều đó chấp nhận được hơn là để toàn bộ tenant mất blocklist vì CSDL đang bảo trì.
type TokenResolver struct {
	db  *Store
	ttl time.Duration
	// MaxStale là thời gian tối đa phục vụ bằng dữ liệu cũ khi CSDL không trả lời.
	maxStale time.Duration

	mu    sync.RWMutex
	cache map[string]tokenEntry
}

type tokenEntry struct {
	slug    string
	found   bool
	fetched time.Time
}

// NewTokenResolver dựng bộ tra với thời gian sống của đệm.
//
// ttl hoặc maxStale <= 0 sẽ rơi vào giá trị mặc định (5 phút và 1 giờ), KHÔNG phải
// "tắt đệm": một bên gọi quên đặt giá trị mà bị mất đệm sẽ dội tải lên CSDL ở mọi
// request, nên mặc định phải nghiêng về phía an toàn.
//
// Hệ quả vận hành: thu hồi một token mất tối đa một TTL để có hiệu lực. Admin API phải
// gọi Invalidate ngay sau khi thu hồi để nó có tác dụng tức thì.
func NewTokenResolver(db *Store, ttl, maxStale time.Duration) *TokenResolver {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	if maxStale <= 0 {
		maxStale = time.Hour
	}
	return &TokenResolver{
		db: db, ttl: ttl, maxStale: maxStale,
		cache: map[string]tokenEntry{},
	}
}

// ErrUnknownToken báo token không tra được.
var ErrUnknownToken = fmt.Errorf("store: token không hợp lệ")

// Resolve trả về slug tenant ứng với token.
func (r *TokenResolver) Resolve(ctx context.Context, raw string) (string, error) {
	hash := HashToken(raw)
	now := time.Now()

	r.mu.RLock()
	entry, cached := r.cache[hash]
	r.mu.RUnlock()

	if cached && now.Sub(entry.fetched) < r.ttl {
		return entry.result()
	}

	slug, found, err := r.lookup(ctx, hash)
	if err != nil {
		// CSDL không trả lời: dùng dữ liệu cũ nếu còn trong hạn.
		if cached && now.Sub(entry.fetched) < r.maxStale {
			return entry.result()
		}
		return "", err
	}

	r.mu.Lock()
	r.cache[hash] = tokenEntry{slug: slug, found: found, fetched: now}
	r.mu.Unlock()

	if !found {
		return "", ErrUnknownToken
	}
	return slug, nil
}

func (e tokenEntry) result() (string, error) {
	if !e.found {
		return "", ErrUnknownToken
	}
	return e.slug, nil
}

func (r *TokenResolver) lookup(ctx context.Context, hash string) (string, bool, error) {
	var slug string
	err := r.db.pool.QueryRow(ctx, `
		SELECT t.slug
		  FROM tenant_tokens tt
		  JOIN tenants t ON t.id = tt.tenant_id
		 WHERE tt.token_hash = $1
		   AND tt.revoked_at IS NULL
		   AND (tt.expires_at IS NULL OR tt.expires_at > NOW())
		   AND t.enabled`, hash).Scan(&slug)

	if err == pgx.ErrNoRows {
		// Token sai cũng được đệm: nếu không, một đợt dò token sẽ biến thành một đợt
		// truy vấn CSDL.
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("store: tra token: %w", err)
	}

	// Ghi nhận lần dùng ở đây, tức là nhiều nhất một lần mỗi TTL cho mỗi token, chứ
	// không phải mỗi request. Blocky làm mới danh sách rất thường xuyên; ghi mỗi lần
	// sẽ biến một endpoint chỉ đọc thành nguồn tải ghi liên tục lên CSDL.
	if _, err := r.db.pool.Exec(ctx,
		"UPDATE tenant_tokens SET last_used_at = NOW() WHERE token_hash = $1", hash); err != nil {
		// Không làm hỏng request chỉ vì không ghi được dấu thời gian.
		_ = err
	}
	return slug, true, nil
}

// Invalidate xóa một token khỏi đệm, dùng ngay sau khi thu hồi để không phải chờ hết TTL.
func (r *TokenResolver) Invalidate(raw string) {
	r.mu.Lock()
	delete(r.cache, HashToken(raw))
	r.mu.Unlock()
}
