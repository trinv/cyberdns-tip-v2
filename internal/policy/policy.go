// Package policy quyết định một domain có vào blocklist của một category hay không.
//
// Evaluate là hàm thuần: cùng đầu vào luôn cho cùng đầu ra, không đọc đồng hồ (thời
// điểm truyền vào qua Input.Now), không chạm CSDL, không chạm mạng. Đây là tầng L2 của
// mô hình suy dẫn — chạy lại trên cùng dữ liệu L1 phải tái tạo đúng quyết định cũ, nếu
// không thì khả năng dựng lại toàn hệ mất hiệu lực.
//
// Quyết định khóa theo (domain, category) chứ không theo domain: đầu ra là file theo
// category và mỗi category có ngưỡng riêng, nên một domain có thể BLOCK ở malware mà
// không BLOCK ở ads.
package policy

import (
	"fmt"
	"slices"
	"time"
)

// Action khớp enum policy_action trong CSDL.
type Action string

const (
	Block   Action = "BLOCK"
	Monitor Action = "MONITOR"
	Allow   Action = "ALLOW"
)

// Origin cho biết bản ghi nguồn do bên nào ghi. Đây là cột thực thi bất biến
// một-bên-ghi-cho-mỗi-nguồn, và là thứ chặn vòng lặp phản hồi khi đếm nguồn độc lập.
type Origin string

const (
	// OriginDirect: feed-ingestor ghi trực tiếp từ nguồn ngoài.
	OriginDirect Origin = "direct"
	// OriginOpenCTI: sync-consumer ghi từ Live Stream của OpenCTI.
	OriginOpenCTI Origin = "opencti"
)

// ReasonCode nêu chính xác nấc nào trong thang ưu tiên đã ra quyết định. Mọi quyết định
// đều phải giải thích được (CLAUDE.md quy tắc 9).
type ReasonCode string

const (
	ReasonProtectedAllowlist  ReasonCode = "global_protected_allowlist"
	ReasonTenantAllowlist     ReasonCode = "tenant_allowlist"
	ReasonTenantDenylist      ReasonCode = "tenant_denylist"
	ReasonGlobalAllowlist     ReasonCode = "global_allowlist"
	ReasonOpenCTIRevoked      ReasonCode = "opencti_revoked"
	ReasonGlobalBlockOverride ReasonCode = "manual_global_block"
	ReasonScoreThreshold      ReasonCode = "score_threshold"
	ReasonBelowThreshold      ReasonCode = "below_threshold"
	ReasonNoEvidence          ReasonCode = "no_active_evidence"
)

// Evidence là khẳng định của MỘT nguồn về một domain trong một category.
type Evidence struct {
	SourceID   string
	Origin     Origin
	TrustScore int // 0..100, cấu hình theo nguồn
	Confidence int // 0..100, do nguồn cung cấp
	LastSeen   time.Time

	// ValidUntil hết hạn là phân rã THỤ ĐỘNG: chỉ rút đóng góp của chính nguồn này,
	// các nguồn khác vẫn đứng nguyên.
	ValidUntil *time.Time

	// RevokedAt là phủ định TƯỜNG MINH. Với nguồn OpenCTI, nó triệt tiêu mọi nguồn
	// khác (nấc 5). Với nguồn direct, nó chỉ vô hiệu hóa bản ghi của nguồn đó — feed
	// không "thu hồi", chúng chỉ ngừng liệt kê.
	RevokedAt *time.Time
}

func (e Evidence) active(now time.Time) bool {
	if e.RevokedAt != nil && !e.RevokedAt.After(now) {
		return false
	}
	if e.ValidUntil != nil && !e.ValidUntil.After(now) {
		return false
	}
	return true
}

// Input là toàn bộ dữ liệu cần để quyết định một cặp (domain, category).
//
// Các cờ danh sách đã được bên gọi giải quyết sẵn, BAO GỒM cả việc khớp theo tổ tiên:
// nếu "*.example.com" nằm trong allowlist thì InTenantAllowlist của "shop.example.com"
// phải bằng true. Tra cứu là việc của tầng lưu trữ; ở đây chỉ còn logic quyết định.
type Input struct {
	Domain   string
	Category string
	Evidence []Evidence

	InProtectedAllowlist  bool
	InTenantAllowlist     bool
	InTenantDenylist      bool
	InGlobalAllowlist     bool
	InGlobalBlockOverride bool

	Now time.Time
}

// CategoryPolicy là ngưỡng của một category.
type CategoryPolicy struct {
	MinScore int
}

// Config là cấu hình chấm điểm.
type Config struct {
	Version       string
	DefaultAction Action

	Categories map[string]CategoryPolicy

	// IndependentSourceBonus cộng thêm cho mỗi nguồn ĐỘC LẬP từ nguồn thứ hai trở đi.
	IndependentSourceBonus int
	MaxIndependentBonus    int

	// StalenessPenaltyPerDay trừ dần theo số ngày kể từ lần nhìn thấy gần nhất.
	StalenessPenaltyPerDay int
	MaxStalenessPenalty    int
}

// DefaultConfig là cấu hình khởi điểm hợp lý, khớp ví dụ trong docs/IMPLEMENTATION.md.
func DefaultConfig() Config {
	return Config{
		Version:       "v1",
		DefaultAction: Monitor,
		Categories: map[string]CategoryPolicy{
			"malware":  {MinScore: 70},
			"phishing": {MinScore: 70},
			"c2":       {MinScore: 70},
			"scam":     {MinScore: 80},
			"ads":      {MinScore: 50},
			"tracking": {MinScore: 50},
			"adults":   {MinScore: 60},
			"gambling": {MinScore: 60},
		},
		IndependentSourceBonus: 10,
		MaxIndependentBonus:    20,
		StalenessPenaltyPerDay: 1,
		MaxStalenessPenalty:    30,
	}
}

// Decision là kết quả, đủ để ghi thẳng vào bảng domain_decisions.
type Decision struct {
	Action                 Action
	Score                  int
	IndependentSourceCount int
	ReasonCode             ReasonCode
	MatchedRules           []string
}

// Evaluate chạy thang ưu tiên; nấc khớp đầu tiên thắng.
//
//  1. global_protected_allowlist  -> ALLOW  (cứng, không ai override được)
//  2. tenant_allowlist            -> ALLOW
//  3. tenant_denylist             -> BLOCK
//  4. global_allowlist (soft)     -> ALLOW
//  5. opencti.revoked             -> ALLOW  (phủ định tường minh)
//  6. manual_global_block         -> BLOCK
//  7. score >= ngưỡng category    -> BLOCK
//  8. mặc định                    -> MONITOR
//
// Thứ tự là một quan hệ toàn phần, không có chỗ cho hòa hay ngẫu nhiên (xung đột C5).
func Evaluate(in Input, cfg Config) Decision {
	score, independent, rules := score(in, cfg)

	base := Decision{
		Score:                  score,
		IndependentSourceCount: independent,
		MatchedRules:           rules,
	}

	// Nấc 1. Lớp chống thảm họa: không tenant nào và không policy nào gỡ được.
	if in.InProtectedAllowlist {
		return finish(base, Allow, ReasonProtectedAllowlist)
	}
	// Nấc 2.
	if in.InTenantAllowlist {
		return finish(base, Allow, ReasonTenantAllowlist)
	}
	// Nấc 3. Tenant tự chịu trách nhiệm với denylist của mình, và nó thắng allowlist
	// mềm toàn cục.
	if in.InTenantDenylist {
		return finish(base, Block, ReasonTenantDenylist)
	}
	// Nấc 4.
	if in.InGlobalAllowlist {
		return finish(base, Allow, ReasonGlobalAllowlist)
	}
	// Nấc 5. Analyst thu hồi trong OpenCTI thì domain ra khỏi blocklist, bất kể bao
	// nhiêu feed còn đang khẳng định nó xấu.
	if revokedByOpenCTI(in) {
		return finish(base, Allow, ReasonOpenCTIRevoked)
	}
	// Nấc 6.
	if in.InGlobalBlockOverride {
		return finish(base, Block, ReasonGlobalBlockOverride)
	}
	// Nấc 7.
	if len(rules) == 0 {
		return finish(base, cfg.DefaultAction, ReasonNoEvidence)
	}
	if pol, ok := cfg.Categories[in.Category]; ok && score >= pol.MinScore {
		return finish(base, Block, ReasonScoreThreshold)
	}
	// Nấc 8.
	return finish(base, cfg.DefaultAction, ReasonBelowThreshold)
}

func finish(d Decision, a Action, r ReasonCode) Decision {
	d.Action = a
	d.ReasonCode = r
	return d
}

// revokedByOpenCTI chỉ xét bản ghi có Origin = opencti.
//
// Feed không "thu hồi" — chúng chỉ ngừng liệt kê, và điều đó được xử lý bằng grace
// period ở tầng lưu trữ. Coi một cờ revoked của feed là phủ định tường minh sẽ biến
// một lỗi build phía nguồn thành đợt gỡ chặn hàng loạt.
func revokedByOpenCTI(in Input) bool {
	for _, e := range in.Evidence {
		if e.Origin == OriginOpenCTI && e.RevokedAt != nil && !e.RevokedAt.After(in.Now) {
			return true
		}
	}
	return false
}

// score tính điểm hiệu dụng, số nguồn độc lập và danh sách rule đã khớp.
func score(in Input, cfg Config) (int, int, []string) {
	var (
		best        int
		newest      time.Time
		independent = map[string]bool{}
		rules       []string
	)

	for _, e := range in.Evidence {
		if !e.active(in.Now) {
			continue
		}

		// Điểm nền là bản ghi thuyết phục nhất: nguồn đáng tin nhất, tự tin nhất.
		if s := e.TrustScore * e.Confidence / 100; s > best {
			best = s
		}
		if e.LastSeen.After(newest) {
			newest = e.LastSeen
		}

		// CHỈ nguồn direct mới được tính là nguồn độc lập.
		//
		// feed-ingestor đẩy domain sang OpenCTI rồi sync-consumer kéo ngược về, nên
		// một domain chỉ đến từ MỘT feed vẫn sẽ có hai hàng nguồn. Đếm cả hai thì mọi
		// domain đi qua OpenCTI đều tự thưởng cho mình một nguồn ảo, điểm lệch có hệ
		// thống và domain bị chặn oan (xung đột B3).
		if e.Origin == OriginDirect {
			independent[e.SourceID] = true
		}
		rules = append(rules, string(e.Origin)+":"+e.SourceID)
	}

	if len(rules) == 0 {
		return 0, 0, nil
	}

	// Thứ tự ổn định: cùng bằng chứng phải cho cùng matched_rules, bất kể thứ tự hàng
	// mà CSDL trả về.
	slices.Sort(rules)
	rules = slices.Compact(rules)

	total := best + independentBonus(len(independent), cfg) - stalenessPenalty(newest, in.Now, cfg)
	return clamp(total, 0, 100), len(independent), rules
}

func independentBonus(n int, cfg Config) int {
	if n < 2 {
		return 0
	}
	return min((n-1)*cfg.IndependentSourceBonus, cfg.MaxIndependentBonus)
}

func stalenessPenalty(lastSeen, now time.Time, cfg Config) int {
	if lastSeen.IsZero() || !now.After(lastSeen) {
		return 0
	}
	days := int(now.Sub(lastSeen).Hours() / 24)
	return min(days*cfg.StalenessPenaltyPerDay, cfg.MaxStalenessPenalty)
}

func clamp(v, lo, hi int) int { return max(lo, min(v, hi)) }

// Validate kiểm tra cấu hình trước khi chạy một lượt policy.
func (c Config) Validate() error {
	if c.Version == "" {
		return fmt.Errorf("policy: thiếu version")
	}
	switch c.DefaultAction {
	case Block, Monitor, Allow:
	default:
		return fmt.Errorf("policy: default_action không hợp lệ %q", c.DefaultAction)
	}
	if len(c.Categories) == 0 {
		return fmt.Errorf("policy: chưa cấu hình category nào")
	}
	for name, p := range c.Categories {
		if p.MinScore < 0 || p.MinScore > 100 {
			return fmt.Errorf("policy: category %q có min_score %d, phải nằm trong 0..100", name, p.MinScore)
		}
	}
	return nil
}
