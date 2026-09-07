package adminapi

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/vnnic/cyberdns-tip/internal/domainname"
)

// maxBody giới hạn kích thước thân yêu cầu. Không endpoint nào ở đây nhận dữ liệu lớn.
const maxBody = 64 * 1024

// staleAfter là ngưỡng coi một nguồn là cũ trên màn hình tổng quan.
const staleAfter = 24 * time.Hour

// Handler trả về bộ định tuyến của API.
func (a *API) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/auth/login", a.handleLogin)
	mux.HandleFunc("POST /api/auth/logout", a.handleLogout)
	mux.HandleFunc("GET /api/auth/me", a.authenticated("", a.handleMe))

	mux.HandleFunc("GET /api/overview", a.authenticated("domain:read", a.handleOverview))

	mux.HandleFunc("GET /api/sources", a.authenticated("source:read", a.handleListSources))
	mux.HandleFunc("POST /api/sources", a.authenticated("source:write", a.handleCreateSource))
	mux.HandleFunc("PATCH /api/sources/{id}", a.authenticated("source:write", a.handleUpdateSource))
	mux.HandleFunc("DELETE /api/sources/{id}", a.authenticated("source:write", a.handleDeleteSource))

	mux.HandleFunc("GET /api/imports", a.authenticated("import:read", a.handleImports))

	mux.HandleFunc("GET /api/domains/lookup", a.authenticated("domain:read", a.handleLookup))

	mux.HandleFunc("GET /api/allowlist", a.authenticated("allowlist:read", a.handleListAllowlist))
	mux.HandleFunc("POST /api/allowlist", a.authenticated("allowlist:write", a.handleAddAllowlist))
	mux.HandleFunc("DELETE /api/allowlist/{id}", a.authenticated("allowlist:write", a.handleDeleteAllowlist))

	// Giao diện nhận mọi đường dẫn còn lại. Đăng ký sau các route /api/ nên ServeMux
	// vẫn ưu tiên chúng: mẫu cụ thể hơn luôn thắng mẫu "/".
	if a.UI != nil {
		mux.Handle("/", a.UI)
	}

	return mux
}

// ---------------------------------------------------------------- tổng quan

func (a *API) handleOverview(w http.ResponseWriter, r *http.Request) {
	o, err := a.DB.Overview(r.Context(), staleAfter)
	if err != nil {
		a.fail(w, "đọc tổng quan", err)
		return
	}
	writeJSON(w, http.StatusOK, o)
}

// ---------------------------------------------------------------- nguồn feed

func (a *API) handleListSources(w http.ResponseWriter, r *http.Request) {
	srcs, err := a.DB.SourcesWithStatus(r.Context())
	if err != nil {
		a.fail(w, "đọc danh sách nguồn", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": srcs})
}

type sourceRequest struct {
	Name             string   `json:"name"`
	URL              string   `json:"url"`
	Type             string   `json:"type"`
	TrustScore       *int     `json:"trust_score"`
	Enabled          *bool    `json:"enabled"`
	RefreshInterval  *int     `json:"refresh_interval_seconds"`
	GracePeriod      *int     `json:"grace_period_seconds"`
	MaxChangeRatio   *float64 `json:"max_change_ratio"`
	MaxResponseBytes *int64   `json:"max_response_bytes"`
	License          *string  `json:"license"`
	Attribution      *string  `json:"attribution"`
	Categories       []string `json:"categories"`
}

func (a *API) handleCreateSource(w http.ResponseWriter, r *http.Request) {
	var req sourceRequest
	if !decode(w, r, &req) {
		return
	}
	if req.Name == "" || req.URL == "" {
		writeError(w, http.StatusBadRequest, "cần có name và url")
		return
	}
	if req.Type == "" {
		req.Type = "plain"
	}

	// Bật một nguồn chưa khai báo license là quyết định có hệ quả pháp lý: hệ tái
	// phát hành list dẫn xuất qua endpoint công khai.
	if req.Enabled != nil && *req.Enabled && (req.License == nil || *req.License == "") {
		writeError(w, http.StatusBadRequest,
			"phải khai báo license trước khi bật nguồn: hệ tái phát hành list dẫn xuất ra ngoài")
		return
	}

	cats, err := json.Marshal(map[string]any{"categories": req.Categories})
	if err != nil {
		a.fail(w, "mã hóa category", err)
		return
	}

	var id int64
	err = a.DB.Pool().QueryRow(r.Context(), `
		INSERT INTO sources (name, url, source_type, origin, trust_score, enabled,
		                     refresh_interval_seconds, grace_period_seconds,
		                     license, attribution, config)
		VALUES ($1, $2, $3, 'direct', COALESCE($4::smallint, 50), COALESCE($5::boolean, FALSE),
		        $6::int, COALESCE($7::int, 604800), $8, $9, $10::jsonb)
		RETURNING id`,
		req.Name, req.URL, req.Type, req.TrustScore, req.Enabled,
		req.RefreshInterval, req.GracePeriod, req.License, req.Attribution, string(cats)).Scan(&id)
	if err != nil {
		a.fail(w, "tạo nguồn", err)
		return
	}

	a.audit(r, "source.create", "source", strconv.FormatInt(id, 10), nil, req)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id})
}

func (a *API) handleUpdateSource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var req sourceRequest
	if !decode(w, r, &req) {
		return
	}

	before, err := a.DB.SourceByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "không có nguồn này")
		return
	}

	// Cùng lý do như lúc tạo: không được bật một nguồn chưa khai báo license.
	license := before.License
	if req.License != nil {
		license = *req.License
	}
	if req.Enabled != nil && *req.Enabled && license == "" {
		writeError(w, http.StatusBadRequest,
			"phải khai báo license trước khi bật nguồn: hệ tái phát hành list dẫn xuất ra ngoài")
		return
	}

	var cats *string
	if req.Categories != nil {
		raw, err := json.Marshal(map[string]any{"categories": req.Categories})
		if err != nil {
			a.fail(w, "mã hóa category", err)
			return
		}
		s := string(raw)
		cats = &s
	}

	_, err = a.DB.Pool().Exec(r.Context(), `
		UPDATE sources SET
		  url                      = COALESCE($2, url),
		  trust_score              = COALESCE($3::smallint, trust_score),
		  enabled                  = COALESCE($4::boolean, enabled),
		  refresh_interval_seconds = COALESCE($5::int, refresh_interval_seconds),
		  grace_period_seconds     = COALESCE($6::int, grace_period_seconds),
		  max_change_ratio         = COALESCE($7::numeric, max_change_ratio),
		  max_response_bytes       = COALESCE($8::bigint, max_response_bytes),
		  license                  = COALESCE($9, license),
		  attribution              = COALESCE($10, attribution),
		  config                   = COALESCE($11::jsonb, config),
		  updated_at               = NOW()
		 WHERE id = $1`,
		id, nullable(req.URL), req.TrustScore, req.Enabled, req.RefreshInterval,
		req.GracePeriod, req.MaxChangeRatio, req.MaxResponseBytes,
		req.License, req.Attribution, cats)
	if err != nil {
		a.fail(w, "cập nhật nguồn", err)
		return
	}

	a.audit(r, "source.update", "source", strconv.FormatInt(id, 10), before, req)
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleDeleteSource(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	before, err := a.DB.SourceByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "không có nguồn này")
		return
	}

	// Xóa nguồn kéo theo mọi bằng chứng L0 của nó qua ON DELETE CASCADE, tức là mất
	// khả năng truy vết. Vì vậy mặc định chỉ TẮT; xóa thật phải yêu cầu tường minh.
	if r.URL.Query().Get("purge") != "true" {
		if _, err := a.DB.Pool().Exec(r.Context(),
			"UPDATE sources SET enabled = FALSE, updated_at = NOW() WHERE id = $1", id); err != nil {
			a.fail(w, "tắt nguồn", err)
			return
		}
		a.audit(r, "source.disable", "source", strconv.FormatInt(id, 10), before, nil)
		w.WriteHeader(http.StatusNoContent)
		return
	}

	if _, err := a.DB.Pool().Exec(r.Context(), "DELETE FROM sources WHERE id = $1", id); err != nil {
		a.fail(w, "xóa nguồn", err)
		return
	}
	a.audit(r, "source.purge", "source", strconv.FormatInt(id, 10), before, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- lịch sử import

func (a *API) handleImports(w http.ResponseWriter, r *http.Request) {
	var sourceID int64
	if s := r.URL.Query().Get("source_id"); s != "" {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			writeError(w, http.StatusBadRequest, "source_id không hợp lệ")
			return
		}
		sourceID = id
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))

	records, err := a.DB.Imports(r.Context(), sourceID, limit)
	if err != nil {
		a.fail(w, "đọc lịch sử import", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"imports": records})
}

// ---------------------------------------------------------------- tra cứu domain

func (a *API) handleLookup(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("domain")
	if raw == "" {
		writeError(w, http.StatusBadRequest, "thiếu tham số domain")
		return
	}

	// Chuẩn hóa đầu vào bằng CHÍNH hàm mà đường ingest dùng. Tra cứu bằng chuỗi thô sẽ
	// không tìm thấy gì khi người dùng gõ chữ hoa hay tên miền IDN.
	domain, err := domainname.Canonicalize(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, "domain không hợp lệ: "+err.Error())
		return
	}

	rep, err := a.DB.LookupDomain(r.Context(), domain)
	if err != nil {
		a.fail(w, "tra cứu domain", err)
		return
	}
	writeJSON(w, http.StatusOK, rep)
}

// ---------------------------------------------------------------- allowlist toàn cục

type allowlistEntry struct {
	ID        int64      `json:"id"`
	Domain    string     `json:"domain"`
	MatchType int        `json:"match_type"`
	Tier      string     `json:"tier"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
}

func (a *API) handleListAllowlist(w http.ResponseWriter, r *http.Request) {
	rows, err := a.DB.Pool().Query(r.Context(), `
		SELECT id, domain, match_type, tier::text, COALESCE(reason, ''),
		       expires_at, COALESCE(created_by, ''), created_at
		  FROM global_allowlist ORDER BY domain, match_type`)
	if err != nil {
		a.fail(w, "đọc allowlist", err)
		return
	}
	defer rows.Close()

	entries := []allowlistEntry{}
	for rows.Next() {
		var e allowlistEntry
		if err := rows.Scan(&e.ID, &e.Domain, &e.MatchType, &e.Tier,
			&e.Reason, &e.ExpiresAt, &e.CreatedBy, &e.CreatedAt); err != nil {
			a.fail(w, "quét allowlist", err)
			return
		}
		entries = append(entries, e)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

type allowlistRequest struct {
	Domain    string     `json:"domain"`
	MatchType int        `json:"match_type"`
	Tier      string     `json:"tier"`
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expires_at"`
}

func (a *API) handleAddAllowlist(w http.ResponseWriter, r *http.Request) {
	var req allowlistRequest
	if !decode(w, r, &req) {
		return
	}

	domain, err := domainname.Canonicalize(req.Domain)
	if err != nil {
		writeError(w, http.StatusBadRequest, "domain không hợp lệ: "+err.Error())
		return
	}
	if req.MatchType != 0 && req.MatchType != 1 {
		writeError(w, http.StatusBadRequest, "match_type phải là 0 (exact) hoặc 1 (wildcard)")
		return
	}
	if req.Tier != "protected" && req.Tier != "soft" {
		req.Tier = "soft"
	}

	user := userOf(r.Context())
	// Mức protected là lớp chống thảm họa: không tenant nào và không policy nào gỡ
	// được.
	//
	// Quyền của nó cố tình nằm NGOÀI phạm vi "allowlist:": vai trò operator có
	// "allowlist:*", và theo đúng ngữ nghĩa wildcard thì dấu sao phải phủ mọi thứ bên
	// dưới nó. Đặt một quyền cao hơn vào bên trong phạm vi mà vai trò thấp đã nắm là
	// cách tạo ra một lỗ phân quyền không ai nhìn thấy khi đọc bảng vai trò.
	if req.Tier == "protected" && !user.Can("protected:write") {
		writeError(w, http.StatusForbidden,
			"mức protected cần quyền protected:write")
		return
	}

	var id int64
	err = a.DB.Pool().QueryRow(r.Context(), `
		INSERT INTO global_allowlist (domain, match_type, tier, reason, expires_at, created_by)
		VALUES ($1, $2::smallint, $3::allowlist_tier, NULLIF($4, ''), $5, $6)
		ON CONFLICT (domain, match_type) DO UPDATE
		   SET tier = EXCLUDED.tier, reason = EXCLUDED.reason,
		       expires_at = EXCLUDED.expires_at, created_by = EXCLUDED.created_by
		RETURNING id`,
		domain, req.MatchType, req.Tier, req.Reason, req.ExpiresAt, user.Email).Scan(&id)
	if err != nil {
		a.fail(w, "thêm allowlist", err)
		return
	}

	a.audit(r, "allowlist.add", "global_allowlist", strconv.FormatInt(id, 10), nil, req)
	writeJSON(w, http.StatusCreated, map[string]any{"id": id, "domain": domain})
}

func (a *API) handleDeleteAllowlist(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r)
	if !ok {
		return
	}

	var before allowlistEntry
	err := a.DB.Pool().QueryRow(r.Context(), `
		SELECT id, domain, match_type, tier::text, COALESCE(reason, '')
		  FROM global_allowlist WHERE id = $1`, id).
		Scan(&before.ID, &before.Domain, &before.MatchType, &before.Tier, &before.Reason)
	if err != nil {
		writeError(w, http.StatusNotFound, "không có mục này")
		return
	}

	user := userOf(r.Context())
	if before.Tier == "protected" && !user.Can("protected:write") {
		writeError(w, http.StatusForbidden, "gỡ mục protected cần quyền protected:write")
		return
	}

	if _, err := a.DB.Pool().Exec(r.Context(),
		"DELETE FROM global_allowlist WHERE id = $1", id); err != nil {
		a.fail(w, "xóa allowlist", err)
		return
	}

	a.audit(r, "allowlist.remove", "global_allowlist", strconv.FormatInt(id, 10), before, nil)
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------- tiện ích

func (a *API) audit(r *http.Request, action, entity, id string, before, after any) {
	user := userOf(r.Context())
	if err := a.DB.Audit(r.Context(), user.Email, action, entity, id, before, after); err != nil {
		// Không làm hỏng thao tác vì không ghi được nhật ký, nhưng phải kêu to: nhật
		// ký hỏng là mất khả năng giải trình.
		a.Log.Error("không ghi được nhật ký quản trị",
			"action", action, "entity", entity, "id", id, "err", err)
	}
}

// fail ghi log chi tiết rồi trả về thông báo chung.
//
// Không trả lỗi gốc ra ngoài: nó chứa cấu trúc bảng và đôi khi cả dữ liệu.
func (a *API) fail(w http.ResponseWriter, what string, err error) {
	a.Log.Error(what, "err", err)
	writeError(w, http.StatusInternalServerError, "lỗi hệ thống")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	// Trường lạ là lỗi: gõ nhầm tên trường mà im lặng bỏ qua sẽ khiến người dùng tưởng
	// đã lưu được thay đổi.
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "thân yêu cầu không hợp lệ: "+err.Error())
		return false
	}
	return true
}

func pathID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeError(w, http.StatusBadRequest, "id không hợp lệ")
		return 0, false
	}
	return id, true
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	// Dashboard không bao giờ được cache: nó hiển thị trạng thái vận hành thời điểm này.
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
