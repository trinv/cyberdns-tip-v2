// Package adminapi cung cấp REST API cho dashboard quản trị.
//
// Hai nguyên tắc xuyên suốt:
//
//   - Mọi thao tác GHI đều ghi nhật ký quản trị. Một thay đổi chính sách chặn không
//     truy được người thực hiện là một thay đổi không giải trình được.
//   - Quyền kiểm tra ở tầng handler chứ không ở tầng giao diện. Giao diện chỉ ẩn nút;
//     nó không phải là hàng rào.
package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/store"
)

// sessionCookie là tên cookie phiên.
const sessionCookie = "cyberdns_session"

// sessionTTL là thời gian sống của một phiên đăng nhập.
const sessionTTL = 12 * time.Hour

type ctxKey int

const userKey ctxKey = 0

// API là bộ handler của dashboard.
type API struct {
	DB  *store.Store
	Log *slog.Logger
	// Secure đặt cờ Secure trên cookie. Tắt khi chạy HTTP cục bộ, bật ở production.
	Secure bool
	// OnRevokeTenantToken được gọi sau khi thu hồi token tenant, để bộ tra token xóa
	// đệm ngay thay vì chờ hết TTL.
	OnRevokeTenantToken func(raw string)
	// UI phục vụ giao diện quản trị. Nil thì service chỉ có API.
	UI http.Handler
}

// userOf lấy tài khoản đã xác thực khỏi context.
func userOf(ctx context.Context) store.AdminUser {
	u, _ := ctx.Value(userKey).(store.AdminUser)
	return u
}

// authenticated bọc handler bằng kiểm tra phiên và quyền.
//
// perm rỗng nghĩa là chỉ cần đăng nhập.
func (a *API) authenticated(perm string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "chưa đăng nhập")
			return
		}

		user, err := a.DB.Session(r.Context(), c.Value)
		if err != nil {
			if !errors.Is(err, store.ErrNoSession) {
				a.Log.Error("đọc phiên", "err", err)
			}
			a.clearCookie(w)
			writeError(w, http.StatusUnauthorized, "phiên không hợp lệ hoặc đã hết hạn")
			return
		}

		if perm != "" && !user.Can(perm) {
			// 403 chứ không phải 404: người dùng đã xác thực, họ chỉ thiếu quyền, và
			// biết điều đó giúp họ đi xin quyền đúng chỗ.
			writeError(w, http.StatusForbidden, "không có quyền "+perm)
			return
		}

		h(w, r.WithContext(context.WithValue(r.Context(), userKey, user)))
	}
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "thân yêu cầu không hợp lệ")
		return
	}

	user, err := a.DB.Authenticate(r.Context(), req.Email, req.Password)
	if err != nil {
		if !errors.Is(err, store.ErrBadCredentials) {
			a.Log.Error("xác thực", "err", err)
			writeError(w, http.StatusInternalServerError, "lỗi hệ thống")
			return
		}
		// Log lần đăng nhập hỏng: đây là tín hiệu dò mật khẩu.
		a.Log.Warn("đăng nhập thất bại", "email", req.Email, "ip", clientIP(r))
		writeError(w, http.StatusUnauthorized, "email hoặc mật khẩu không đúng")
		return
	}

	token, err := a.DB.CreateSession(r.Context(), user.ID, sessionTTL,
		r.UserAgent(), clientIP(r))
	if err != nil {
		a.Log.Error("tạo phiên", "err", err)
		writeError(w, http.StatusInternalServerError, "lỗi hệ thống")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:  sessionCookie,
		Value: token,
		Path:  "/",
		// HttpOnly: script trên trang không đọc được cookie, nên một lỗ XSS không
		// đồng nghĩa với mất phiên.
		HttpOnly: true,
		Secure:   a.Secure,
		// SameSite=Lax chặn CSRF cho mọi request đổi trạng thái từ site khác.
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(sessionTTL),
	})

	a.Log.Info("đăng nhập", "email", user.Email, "ip", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{
		"email":       user.Email,
		"displayName": user.DisplayName,
		"role":        user.Role,
		"permissions": user.Permissions,
	})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		if err := a.DB.RevokeSession(r.Context(), c.Value); err != nil {
			a.Log.Error("thu hồi phiên", "err", err)
		}
	}
	a.clearCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userOf(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"email":       u.Email,
		"displayName": u.DisplayName,
		"role":        u.Role,
		"permissions": u.Permissions,
	})
}

func (a *API) clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: sessionCookie, Value: "", Path: "/",
		HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteLaxMode,
		MaxAge: -1,
	})
}

// clientIP lấy địa chỉ client, ưu tiên header do reverse proxy đặt.
//
// Chỉ tin X-Forwarded-For khi service đứng sau proxy của chính mình — ở đây luôn đúng
// vì admin-api không bao giờ phơi thẳng ra Internet.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if first, _, ok := strings.Cut(xff, ","); ok {
			return strings.TrimSpace(first)
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
