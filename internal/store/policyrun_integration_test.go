package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/vnnic/cyberdns-tip/internal/domainname"
	"github.com/vnnic/cyberdns-tip/internal/policy"
	"github.com/vnnic/cyberdns-tip/internal/store"
)

// runPolicy chạy trọn một lượt policy và trả về số liệu.
func runPolicy(t *testing.T, s *store.Store, cfg policy.Config, at time.Time) store.RunStats {
	t.Helper()
	ctx := context.Background()

	runID, err := s.BeginPolicyRun(ctx, cfg, false)
	if err != nil {
		t.Fatalf("BeginPolicyRun: %v", err)
	}
	lists, err := s.LoadLists(ctx, at)
	if err != nil {
		t.Fatalf("LoadLists: %v", err)
	}
	stats, err := s.EvaluateAll(ctx, runID, cfg, lists, at)
	if err != nil {
		t.Fatalf("EvaluateAll: %v", err)
	}
	if err := s.FinishPolicyRun(ctx, runID, "completed", stats.Evaluated, stats.Blocked, ""); err != nil {
		t.Fatalf("FinishPolicyRun: %v", err)
	}
	return stats
}

func decisionOf(t *testing.T, pool *pgxpool.Pool, domain, category string) (string, int, string) {
	t.Helper()
	var action, reason string
	var score int
	err := pool.QueryRow(context.Background(), `
		SELECT dd.action::text, dd.effective_score, dd.reason_code
		  FROM domain_decisions dd
		  JOIN domains d    ON d.id = dd.domain_id
		  JOIN categories c ON c.id = dd.category_id
		 WHERE d.normalized_domain = $1 AND c.name = $2`, domain, category).
		Scan(&action, &score, &reason)
	if err != nil {
		t.Fatalf("đọc quyết định (%s, %s): %v", domain, category, err)
	}
	return action, score, reason
}

func TestEvaluateAllWritesDecisions(t *testing.T) {
	s, pool := newStore(t)
	// trust 90 x confidence 90 = 81, vượt ngưỡng malware (70).
	src := addSource(t, pool, "t-hagezi", `["malware"]`, 604800)

	apply(t, s, src, "v1", baseTime,
		rec("evil.example.com", domainname.Exact),
		rec("bad.example.net", domainname.Exact),
	)

	stats := runPolicy(t, s, policy.DefaultConfig(), baseTime)

	if stats.Evaluated != 2 {
		t.Errorf("Evaluated = %d, muốn 2", stats.Evaluated)
	}
	if stats.Blocked != 2 {
		t.Errorf("Blocked = %d, muốn 2", stats.Blocked)
	}

	action, score, reason := decisionOf(t, pool, "evil.example.com", "malware")
	if action != "BLOCK" {
		t.Errorf("action = %s, muốn BLOCK (điểm %d, lý do %s)", action, score, reason)
	}
	if reason != string(policy.ReasonScoreThreshold) {
		t.Errorf("reason = %s, muốn score_threshold", reason)
	}
}

// Nấc 1 của thang ưu tiên, kiểm tra xuyên suốt từ CSDL: khớp theo tổ tiên phải hoạt
// động, nghĩa là allowlist wildcard ở example.com phủ luôn shop.example.com.
func TestProtectedAllowlistBeatsEverything(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "t-hagezi", `["malware"]`, 604800)
	ctx := context.Background()

	if _, err := pool.Exec(ctx, `
		INSERT INTO global_allowlist (domain, match_type, tier, reason)
		VALUES ('example.com', 1, 'protected', 'hạ tầng trọng yếu')`); err != nil {
		t.Fatalf("thêm allowlist: %v", err)
	}

	apply(t, s, src, "v1", baseTime,
		rec("shop.example.com", domainname.Exact), // con của mục protected
		rec("evil.other.net", domainname.Exact),   // không liên quan
	)

	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	action, _, reason := decisionOf(t, pool, "shop.example.com", "malware")
	if action != "ALLOW" {
		t.Errorf("shop.example.com = %s, muốn ALLOW: nằm dưới mục protected wildcard", action)
	}
	if reason != string(policy.ReasonProtectedAllowlist) {
		t.Errorf("reason = %s, muốn global_protected_allowlist", reason)
	}

	if action, _, _ := decisionOf(t, pool, "evil.other.net", "malware"); action != "BLOCK" {
		t.Errorf("evil.other.net = %s, muốn BLOCK", action)
	}
}

// Mục allowlist đã hết hạn không được có hiệu lực.
func TestExpiredAllowlistEntryIsIgnored(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)

	if _, err := pool.Exec(context.Background(), `
		INSERT INTO global_allowlist (domain, match_type, tier, expires_at)
		VALUES ('evil.example.com', 0, 'protected', $1)`, baseTime.Add(-time.Hour)); err != nil {
		t.Fatalf("thêm allowlist: %v", err)
	}

	apply(t, s, src, "v1", baseTime, rec("evil.example.com", domainname.Exact))
	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	if action, _, _ := decisionOf(t, pool, "evil.example.com", "malware"); action != "BLOCK" {
		t.Errorf("action = %s, muốn BLOCK: mục allowlist đã hết hạn", action)
	}
}

// decision_changes chỉ ghi khi trạng thái THỰC SỰ đổi. Chạy lại trên cùng dữ liệu
// không được sinh thêm hàng nào — ở mốc 10M domain thì đó là khác biệt giữa một bảng
// lịch sử dùng được và một bảng phình vô hạn.
func TestDecisionChangesOnlyRecordTransitions(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)

	apply(t, s, src, "v1", baseTime, rec("evil.example.com", domainname.Exact))

	first := runPolicy(t, s, policy.DefaultConfig(), baseTime)
	if first.Changed != 1 {
		t.Errorf("lượt đầu Changed = %d, muốn 1 (chưa có -> BLOCK)", first.Changed)
	}

	second := runPolicy(t, s, policy.DefaultConfig(), baseTime)
	if second.Changed != 0 {
		t.Errorf("lượt hai Changed = %d, muốn 0: dữ liệu không đổi", second.Changed)
	}
	if n := count(t, pool, "SELECT count(*) FROM decision_changes"); n != 1 {
		t.Errorf("decision_changes = %d, muốn 1", n)
	}

	// Siết ngưỡng để BLOCK thành MONITOR — đây mới là một lần chuyển thật.
	strict := policy.DefaultConfig()
	strict.Categories["malware"] = policy.CategoryPolicy{MinScore: 99}
	third := runPolicy(t, s, strict, baseTime)

	if third.Changed != 1 {
		t.Errorf("sau khi siết ngưỡng Changed = %d, muốn 1", third.Changed)
	}
	if action, _, _ := decisionOf(t, pool, "evil.example.com", "malware"); action != "MONITOR" {
		t.Errorf("action = %s, muốn MONITOR", action)
	}

	var oldAction, newAction string
	if err := pool.QueryRow(context.Background(), `
		SELECT old_action::text, new_action::text FROM decision_changes
		 ORDER BY id DESC LIMIT 1`).Scan(&oldAction, &newAction); err != nil {
		t.Fatalf("đọc decision_changes: %v", err)
	}
	if oldAction != "BLOCK" || newAction != "MONITOR" {
		t.Errorf("chuyển trạng thái ghi nhận là %s -> %s, muốn BLOCK -> MONITOR", oldAction, newAction)
	}
}

// Domain mất hết nguồn thì quyết định của nó phải biến mất, nếu không generator sẽ
// tiếp tục xuất nó mãi mãi.
func TestOrphanDecisionsAreRemoved(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 0) // grace 0

	apply(t, s, src, "v1", baseTime,
		rec("gone.example.com", domainname.Exact),
		rec("stays.example.com", domainname.Exact),
	)
	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	if n := count(t, pool, "SELECT count(*) FROM domain_decisions"); n != 2 {
		t.Fatalf("domain_decisions = %d, muốn 2", n)
	}

	// Nguồn gỡ một domain; hết grace period ngay.
	apply(t, s, src, "v2", baseTime.Add(time.Hour), rec("stays.example.com", domainname.Exact))
	runPolicy(t, s, policy.DefaultConfig(), baseTime.Add(time.Hour))

	if n := count(t, pool, "SELECT count(*) FROM domain_decisions"); n != 1 {
		t.Errorf("domain_decisions = %d, muốn 1 sau khi một domain mất hết nguồn", n)
	}

	rules, err := s.BlockedRules(context.Background(), "malware")
	if err != nil {
		t.Fatalf("BlockedRules: %v", err)
	}
	if len(rules) != 1 || rules[0].Domain != "stays.example.com" {
		t.Errorf("BlockedRules = %v, muốn chỉ còn stays.example.com", rules)
	}
}

// Ngưỡng theo từng category: cùng một bằng chứng cho ra kết quả khác nhau ở hai
// category khác nhau. Đây là lý do quyết định khóa theo (domain, category).
func TestPerCategoryThresholds(t *testing.T) {
	s, pool := newStore(t)
	// trust 90 x confidence 90 = 81: qua ngưỡng malware (70), trượt ngưỡng scam (80)?
	// 81 >= 80 nên vẫn qua. Dùng ngưỡng tùy chỉnh cho rõ ràng.
	src := addSource(t, pool, "feed", `["malware","scam"]`, 604800)

	apply(t, s, src, "v1", baseTime, rec("evil.example.com", domainname.Exact))

	cfg := policy.DefaultConfig()
	cfg.Categories["malware"] = policy.CategoryPolicy{MinScore: 50} // qua
	cfg.Categories["scam"] = policy.CategoryPolicy{MinScore: 95}    // trượt
	runPolicy(t, s, cfg, baseTime)

	if action, score, _ := decisionOf(t, pool, "evil.example.com", "malware"); action != "BLOCK" {
		t.Errorf("malware = %s (điểm %d), muốn BLOCK", action, score)
	}
	if action, score, _ := decisionOf(t, pool, "evil.example.com", "scam"); action != "MONITOR" {
		t.Errorf("scam = %s (điểm %d), muốn MONITOR", action, score)
	}
}

// Xung đột B3, kiểm tra xuyên suốt qua CSDL: domain đi vòng qua OpenCTI không được
// tự thưởng cho mình một nguồn độc lập ảo.
func TestOpenCTIDoesNotInflateIndependentSourceCount(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	feed := addSource(t, pool, "t-hagezi", `["malware"]`, 604800)

	// Nguồn thứ hai mô phỏng dữ liệu quay về từ OpenCTI.
	var octiID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO sources (name, source_type, origin, trust_score, config)
		VALUES ('t-opencti', 'stream', 'opencti', 90, '{"categories": ["malware"]}'::jsonb)
		RETURNING id`).Scan(&octiID); err != nil {
		t.Fatalf("tạo nguồn opencti: %v", err)
	}
	all, err := s.EnabledSources(ctx, "opencti")
	if err != nil {
		t.Fatalf("EnabledSources: %v", err)
	}
	var octiSrcs []store.Source
	for _, src := range all {
		if src.ID == octiID {
			octiSrcs = append(octiSrcs, src)
		}
	}
	if len(octiSrcs) != 1 {
		t.Fatalf("không tìm thấy nguồn opencti vừa tạo (có %d nguồn opencti đang bật)", len(all))
	}

	shared := rec("evil.example.com", domainname.Exact)
	apply(t, s, feed, "v1", baseTime, shared)
	apply(t, s, octiSrcs[0], "v1", baseTime, shared)

	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	var independent int
	if err := pool.QueryRow(ctx, `
		SELECT dd.independent_source_count
		  FROM domain_decisions dd
		  JOIN domains d ON d.id = dd.domain_id
		 WHERE d.normalized_domain = 'evil.example.com'`).Scan(&independent); err != nil {
		t.Fatalf("đọc independent_source_count: %v", err)
	}
	if independent != 1 {
		t.Errorf("independent_source_count = %d, muốn 1: hàng opencti không phải xác nhận độc lập",
			independent)
	}
}

func TestCurrentPolicyRun(t *testing.T) {
	s, pool := newStore(t)
	ctx := context.Background()

	id, err := s.CurrentPolicyRun(ctx)
	if err != nil {
		t.Fatalf("CurrentPolicyRun: %v", err)
	}
	if id != 0 {
		t.Errorf("CurrentPolicyRun = %d khi chưa có lượt nào, muốn 0", id)
	}

	src := addSource(t, pool, "feed", `["malware"]`, 604800)
	apply(t, s, src, "v1", baseTime, rec("evil.example.com", domainname.Exact))
	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	id, err = s.CurrentPolicyRun(ctx)
	if err != nil {
		t.Fatalf("CurrentPolicyRun: %v", err)
	}
	if id == 0 {
		t.Error("CurrentPolicyRun = 0 sau một lượt đã hoàn tất")
	}

	// Lượt shadow không được coi là lượt hiện hành: nó chỉ để so sánh, chưa áp dụng.
	shadowID, err := s.BeginPolicyRun(ctx, policy.DefaultConfig(), true)
	if err != nil {
		t.Fatalf("BeginPolicyRun shadow: %v", err)
	}
	if err := s.FinishPolicyRun(ctx, shadowID, "completed", 0, 0, ""); err != nil {
		t.Fatalf("FinishPolicyRun shadow: %v", err)
	}

	got, err := s.CurrentPolicyRun(ctx)
	if err != nil {
		t.Fatalf("CurrentPolicyRun: %v", err)
	}
	if got == shadowID {
		t.Error("lượt shadow bị coi là lượt hiện hành")
	}
	if got != id {
		t.Errorf("CurrentPolicyRun = %d, muốn giữ nguyên %d", got, id)
	}
}

// BlockedRules phải trả về thứ tự tất định: cùng dữ liệu thì cùng thứ tự, và do đó
// cùng checksum — điều kiện để "chỉ dựng lại khi dữ liệu thực sự đổi" hoạt động.
func TestBlockedRulesIsDeterministicallyOrdered(t *testing.T) {
	s, pool := newStore(t)
	src := addSource(t, pool, "feed", `["malware"]`, 604800)

	apply(t, s, src, "v1", baseTime,
		rec("zebra.example.com", domainname.Exact),
		rec("alpha.example.com", domainname.Exact),
		rec("middle.example.com", domainname.Wildcard),
		rec("middle.example.com", domainname.Exact),
	)
	runPolicy(t, s, policy.DefaultConfig(), baseTime)

	want := []string{"alpha.example.com", "middle.example.com", "middle.example.com", "zebra.example.com"}
	for range 3 {
		rules, err := s.BlockedRules(context.Background(), "malware")
		if err != nil {
			t.Fatalf("BlockedRules: %v", err)
		}
		if len(rules) != len(want) {
			t.Fatalf("BlockedRules trả %d rule, muốn %d", len(rules), len(want))
		}
		for i := range want {
			if rules[i].Domain != want[i] {
				t.Fatalf("rules[%d] = %s, muốn %s", i, rules[i].Domain, want[i])
			}
		}
		// exact (0) đứng trước wildcard (1) ở cùng domain.
		if rules[1].MatchType != domainname.Exact || rules[2].MatchType != domainname.Wildcard {
			t.Errorf("thứ tự match_type sai: %v, %v", rules[1].MatchType, rules[2].MatchType)
		}
	}
}
