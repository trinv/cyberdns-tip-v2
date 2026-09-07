package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

// AdminUser là một tài khoản quản trị.
type AdminUser struct {
	ID          int64
	Email       string
	DisplayName string
	Role        string
	Permissions []string
	// TenantID khác nil nghĩa là tài khoản chỉ quản trị một tenant.
	TenantID *int64
}

// Can cho biết tài khoản có quyền thực hiện hành động không.
//
// Quyền "*" là toàn quyền; "source:*" phủ mọi hành động trên nguồn.
func (u AdminUser) Can(perm string) bool {
	for _, p := range u.Permissions {
		if p == "*" || p == perm {
			return true
		}
		// So khớp tiền tố dạng "source:*".
		if len(p) > 2 && p[len(p)-2:] == ":*" {
			prefix := p[:len(p)-1]
			if len(perm) >= len(prefix) && perm[:len(prefix)] == prefix {
				return true
			}
		}
	}
	return false
}

var (
	// ErrBadCredentials cố tình không phân biệt "email không tồn tại" với "sai mật
	// khẩu": phân biệt hai trường hợp cho phép dò xem địa chỉ nào có tài khoản.
	ErrBadCredentials = errors.New("store: email hoặc mật khẩu không đúng")
	ErrNoSession      = errors.New("store: phiên không hợp lệ")
)

// CreateAdmin tạo hoặc đặt lại mật khẩu một tài khoản quản trị.
func (s *Store) CreateAdmin(ctx context.Context, email, displayName, role, password string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("store: băm mật khẩu: %w", err)
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO admin_users (email, display_name, password_hash, role_id, enabled)
		VALUES ($1, $2, $3, (SELECT id FROM admin_roles WHERE name = $4), TRUE)
		ON CONFLICT (email) DO UPDATE
		   SET password_hash = EXCLUDED.password_hash,
		       display_name  = EXCLUDED.display_name,
		       role_id       = EXCLUDED.role_id,
		       enabled       = TRUE`,
		email, displayName, string(hash), role)
	if err != nil {
		return fmt.Errorf("store: tạo tài khoản quản trị: %w", err)
	}
	return nil
}

// Authenticate kiểm tra email và mật khẩu.
func (s *Store) Authenticate(ctx context.Context, email, password string) (AdminUser, error) {
	var (
		u    AdminUser
		hash string
		perm []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, COALESCE(u.display_name, ''), u.password_hash,
		       COALESCE(r.name, ''), COALESCE(r.permissions, '[]'::jsonb), u.tenant_id
		  FROM admin_users u
		  LEFT JOIN admin_roles r ON r.id = u.role_id
		 WHERE u.email = $1 AND u.enabled`, email).
		Scan(&u.ID, &u.Email, &u.DisplayName, &hash, &u.Role, &perm, &u.TenantID)

	if err == pgx.ErrNoRows {
		// Vẫn tốn thời gian băm một mật khẩu giả để thời gian phản hồi không tiết lộ
		// email nào có tài khoản.
		_, _ = bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
		return AdminUser{}, ErrBadCredentials
	}
	if err != nil {
		return AdminUser{}, fmt.Errorf("store: đọc tài khoản: %w", err)
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		return AdminUser{}, ErrBadCredentials
	}
	if err := json.Unmarshal(perm, &u.Permissions); err != nil {
		return AdminUser{}, fmt.Errorf("store: đọc quyền: %w", err)
	}

	_, _ = s.pool.Exec(ctx, "UPDATE admin_users SET last_login_at = NOW() WHERE id = $1", u.ID)
	return u, nil
}

// CreateSession mở một phiên và trả về token thô để đặt vào cookie.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration, ua, ip string) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("store: sinh token phiên: %w", err)
	}
	raw := base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))

	var addr any
	if a, err := netip.ParseAddr(ip); err == nil {
		addr = a.String()
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_sessions (token_hash, user_id, expires_at, user_agent, ip)
		VALUES ($1, $2, NOW() + make_interval(secs => $3::double precision), NULLIF($4, ''), $5)`,
		hex.EncodeToString(sum[:]), userID, ttl.Seconds(), ua, addr)
	if err != nil {
		return "", fmt.Errorf("store: tạo phiên: %w", err)
	}
	return raw, nil
}

// Session tra một token phiên và trả về tài khoản.
func (s *Store) Session(ctx context.Context, raw string) (AdminUser, error) {
	sum := sha256.Sum256([]byte(raw))

	var (
		u    AdminUser
		perm []byte
	)
	err := s.pool.QueryRow(ctx, `
		SELECT u.id, u.email, COALESCE(u.display_name, ''),
		       COALESCE(r.name, ''), COALESCE(r.permissions, '[]'::jsonb), u.tenant_id
		  FROM admin_sessions s
		  JOIN admin_users u ON u.id = s.user_id
		  LEFT JOIN admin_roles r ON r.id = u.role_id
		 WHERE s.token_hash = $1
		   AND s.revoked_at IS NULL
		   AND s.expires_at > NOW()
		   AND u.enabled`, hex.EncodeToString(sum[:])).
		Scan(&u.ID, &u.Email, &u.DisplayName, &u.Role, &perm, &u.TenantID)

	if err == pgx.ErrNoRows {
		return AdminUser{}, ErrNoSession
	}
	if err != nil {
		return AdminUser{}, fmt.Errorf("store: đọc phiên: %w", err)
	}
	if err := json.Unmarshal(perm, &u.Permissions); err != nil {
		return AdminUser{}, fmt.Errorf("store: đọc quyền: %w", err)
	}

	_, _ = s.pool.Exec(ctx,
		"UPDATE admin_sessions SET last_seen_at = NOW() WHERE token_hash = $1",
		hex.EncodeToString(sum[:]))
	return u, nil
}

// RevokeSession thu hồi một phiên.
func (s *Store) RevokeSession(ctx context.Context, raw string) error {
	sum := sha256.Sum256([]byte(raw))
	_, err := s.pool.Exec(ctx,
		"UPDATE admin_sessions SET revoked_at = NOW() WHERE token_hash = $1",
		hex.EncodeToString(sum[:]))
	if err != nil {
		return fmt.Errorf("store: thu hồi phiên: %w", err)
	}
	return nil
}

// Audit ghi một thay đổi vào nhật ký quản trị.
//
// Mọi thao tác GHI qua dashboard đều phải đi qua đây. Một thay đổi chính sách chặn
// không truy được người thực hiện là một thay đổi không giải trình được.
func (s *Store) Audit(ctx context.Context, actor, action, entity, entityID string, before, after any) error {
	var b, a []byte
	if before != nil {
		b, _ = json.Marshal(before)
	}
	if after != nil {
		a, _ = json.Marshal(after)
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO admin_audit_log (actor, action, entity, entity_id, before, after)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6)`,
		actor, action, entity, entityID, b, a)
	if err != nil {
		return fmt.Errorf("store: ghi nhật ký quản trị: %w", err)
	}
	return nil
}
