package policy

import (
	"slices"
	"testing"
	"time"
)

var now = time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)

func ptr(t time.Time) *time.Time { return &t }

// strongFeed là một bằng chứng thừa sức vượt ngưỡng malware (70) khi đứng một mình:
// 90 * 95 / 100 = 85.
func strongFeed(id string) Evidence {
	return Evidence{
		SourceID:   id,
		Origin:     OriginDirect,
		TrustScore: 90,
		Confidence: 95,
		LastSeen:   now,
	}
}

func base(ev ...Evidence) Input {
	return Input{
		Domain:   "evil.example.com",
		Category: "malware",
		Evidence: ev,
		Now:      now,
	}
}

// Bảng quyết định phủ hết 8 nấc của thang ưu tiên. Đây là bộ test mà PLAN.md Phase 3
// gọi là "100% deterministic test suite for decision matrix".
func TestPrecedenceLadder(t *testing.T) {
	cfg := DefaultConfig()

	revokedOpenCTI := Evidence{
		SourceID: "opencti", Origin: OriginOpenCTI,
		TrustScore: 100, Confidence: 100, LastSeen: now,
		RevokedAt: ptr(now.Add(-time.Hour)),
	}

	tests := []struct {
		name       string
		in         Input
		wantAction Action
		wantReason ReasonCode
	}{
		{
			name: "nấc 1 protected allowlist thắng tất cả",
			in: func() Input {
				i := base(strongFeed("hagezi"), revokedOpenCTI)
				i.InProtectedAllowlist = true
				i.InTenantAllowlist = true
				i.InTenantDenylist = true
				i.InGlobalAllowlist = true
				i.InGlobalBlockOverride = true
				return i
			}(),
			wantAction: Allow,
			wantReason: ReasonProtectedAllowlist,
		},
		{
			name: "nấc 2 tenant allowlist thắng denylist tenant",
			in: func() Input {
				i := base(strongFeed("hagezi"))
				i.InTenantAllowlist = true
				i.InTenantDenylist = true
				return i
			}(),
			wantAction: Allow,
			wantReason: ReasonTenantAllowlist,
		},
		{
			name: "nấc 3 tenant denylist thắng allowlist mềm toàn cục",
			in: func() Input {
				i := base()
				i.InTenantDenylist = true
				i.InGlobalAllowlist = true
				return i
			}(),
			wantAction: Block,
			wantReason: ReasonTenantDenylist,
		},
		{
			name: "nấc 4 allowlist mềm toàn cục",
			in: func() Input {
				i := base(strongFeed("hagezi"))
				i.InGlobalAllowlist = true
				return i
			}(),
			wantAction: Allow,
			wantReason: ReasonGlobalAllowlist,
		},
		{
			name: "nấc 5 OpenCTI thu hồi thắng cả feed lẫn override thủ công",
			in: func() Input {
				i := base(strongFeed("hagezi"), revokedOpenCTI)
				i.InGlobalBlockOverride = true
				return i
			}(),
			wantAction: Allow,
			wantReason: ReasonOpenCTIRevoked,
		},
		{
			name:       "nấc 6 override chặn thủ công khi không có bằng chứng nào",
			in:         func() Input { i := base(); i.InGlobalBlockOverride = true; return i }(),
			wantAction: Block,
			wantReason: ReasonGlobalBlockOverride,
		},
		{
			name:       "nấc 7 vượt ngưỡng category",
			in:         base(strongFeed("hagezi")),
			wantAction: Block,
			wantReason: ReasonScoreThreshold,
		},
		{
			name: "nấc 8 dưới ngưỡng",
			in: base(Evidence{
				SourceID: "weak", Origin: OriginDirect,
				TrustScore: 40, Confidence: 50, LastSeen: now, // 20 < 70
			}),
			wantAction: Monitor,
			wantReason: ReasonBelowThreshold,
		},
		{
			name:       "không có bằng chứng nào",
			in:         base(),
			wantAction: Monitor,
			wantReason: ReasonNoEvidence,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Evaluate(tt.in, cfg)
			if got.Action != tt.wantAction {
				t.Errorf("Action = %v, muốn %v", got.Action, tt.wantAction)
			}
			if got.ReasonCode != tt.wantReason {
				t.Errorf("ReasonCode = %v, muốn %v", got.ReasonCode, tt.wantReason)
			}
		})
	}
}

// Bài test chống vòng lặp phản hồi (xung đột B3), lấy thẳng từ mục Verification của
// kế hoạch. Một domain chỉ đến từ MỘT feed, đi vòng qua OpenCTI rồi quay về, vẫn phải
// được đếm là một nguồn độc lập.
func TestOpenCTIRoundTripDoesNotInflateSourceCount(t *testing.T) {
	cfg := DefaultConfig()

	oneFeed := Evaluate(base(strongFeed("hagezi")), cfg)
	if oneFeed.IndependentSourceCount != 1 {
		t.Fatalf("một feed: IndependentSourceCount = %d, muốn 1", oneFeed.IndependentSourceCount)
	}

	// Cùng domain đó sau khi đi vòng qua OpenCTI: có thêm một hàng nguồn, nhưng nó
	// không phải một xác nhận độc lập — nó là chính dữ liệu ta vừa đẩy sang.
	roundTrip := Evaluate(base(
		strongFeed("hagezi"),
		Evidence{SourceID: "opencti", Origin: OriginOpenCTI, TrustScore: 90, Confidence: 95, LastSeen: now},
	), cfg)

	if roundTrip.IndependentSourceCount != 1 {
		t.Errorf("sau vòng OpenCTI: IndependentSourceCount = %d, muốn vẫn là 1",
			roundTrip.IndependentSourceCount)
	}
	if roundTrip.Score != oneFeed.Score {
		t.Errorf("điểm bị lạm phát: %d -> %d sau khi đi vòng qua OpenCTI",
			oneFeed.Score, roundTrip.Score)
	}

	// Còn hai feed thật sự độc lập thì phải được thưởng.
	twoFeeds := Evaluate(base(strongFeed("hagezi"), strongFeed("urlhaus")), cfg)
	if twoFeeds.IndependentSourceCount != 2 {
		t.Errorf("hai feed: IndependentSourceCount = %d, muốn 2", twoFeeds.IndependentSourceCount)
	}
	if twoFeeds.Score <= oneFeed.Score {
		t.Errorf("hai nguồn độc lập (%d) không được thưởng so với một nguồn (%d)",
			twoFeeds.Score, oneFeed.Score)
	}
}

// Xung đột B2: revoked và valid_until hết hạn KHÔNG đồng nghĩa. Nhầm hai cái này sẽ
// gây gỡ chặn hàng loạt ngoài ý muốn.
func TestRevokedVersusExpired(t *testing.T) {
	cfg := DefaultConfig()
	expired := ptr(now.Add(-24 * time.Hour))

	t.Run("OpenCTI hết hạn chỉ rút đóng góp của chính nó", func(t *testing.T) {
		got := Evaluate(base(
			strongFeed("hagezi"),
			Evidence{
				SourceID: "opencti", Origin: OriginOpenCTI,
				TrustScore: 100, Confidence: 100, LastSeen: now,
				ValidUntil: expired,
			},
		), cfg)

		if got.Action != Block {
			t.Errorf("Action = %v, muốn BLOCK: feed vẫn đang khẳng định domain xấu", got.Action)
		}
		if got.ReasonCode != ReasonScoreThreshold {
			t.Errorf("ReasonCode = %v, muốn score_threshold", got.ReasonCode)
		}
	})

	t.Run("OpenCTI thu hồi triệt tiêu mọi feed", func(t *testing.T) {
		got := Evaluate(base(
			strongFeed("hagezi"), strongFeed("urlhaus"), strongFeed("cert"),
			Evidence{
				SourceID: "opencti", Origin: OriginOpenCTI,
				TrustScore: 100, Confidence: 100, LastSeen: now,
				RevokedAt: expired,
			},
		), cfg)

		if got.Action != Allow || got.ReasonCode != ReasonOpenCTIRevoked {
			t.Errorf("Action/Reason = %v/%v, muốn ALLOW/opencti_revoked dù có 3 feed",
				got.Action, got.ReasonCode)
		}
	})

	// Feed không "thu hồi" — chúng chỉ ngừng liệt kê. Coi cờ revoked của feed là phủ
	// định tường minh sẽ biến một lỗi build phía nguồn thành đợt gỡ chặn hàng loạt.
	t.Run("feed direct thu hồi chỉ vô hiệu hóa chính nó", func(t *testing.T) {
		got := Evaluate(base(
			Evidence{
				SourceID: "hagezi", Origin: OriginDirect,
				TrustScore: 90, Confidence: 95, LastSeen: now,
				RevokedAt: expired,
			},
			strongFeed("urlhaus"),
		), cfg)

		if got.Action != Block {
			t.Errorf("Action = %v, muốn BLOCK: urlhaus vẫn đang khẳng định", got.Action)
		}
		if got.IndependentSourceCount != 1 {
			t.Errorf("IndependentSourceCount = %d, muốn 1 (hagezi đã bị vô hiệu hóa)",
				got.IndependentSourceCount)
		}
	})
}

// Một domain có thể vượt ngưỡng ở category này mà không vượt ở category kia. Đây là lý
// do quyết định phải khóa theo (domain, category) chứ không theo domain.
func TestThresholdIsPerCategory(t *testing.T) {
	cfg := DefaultConfig()

	// 60 * 100 / 100 = 60: qua ngưỡng ads (50), trượt ngưỡng malware (70).
	ev := Evidence{SourceID: "hagezi", Origin: OriginDirect, TrustScore: 60, Confidence: 100, LastSeen: now}

	ads := base(ev)
	ads.Category = "ads"
	if got := Evaluate(ads, cfg); got.Action != Block {
		t.Errorf("ads: Action = %v (điểm %d), muốn BLOCK", got.Action, got.Score)
	}

	malware := base(ev)
	malware.Category = "malware"
	if got := Evaluate(malware, cfg); got.Action != Monitor {
		t.Errorf("malware: Action = %v (điểm %d), muốn MONITOR", got.Action, got.Score)
	}
}

func TestStalenessPenalty(t *testing.T) {
	cfg := DefaultConfig()

	fresh := Evaluate(base(strongFeed("hagezi")), cfg)

	stale := strongFeed("hagezi")
	stale.LastSeen = now.Add(-40 * 24 * time.Hour)
	old := Evaluate(base(stale), cfg)

	if old.Score >= fresh.Score {
		t.Errorf("bằng chứng cũ 40 ngày (%d) không bị trừ điểm so với bằng chứng mới (%d)",
			old.Score, fresh.Score)
	}
	// Trừ có trần: bằng chứng cũ không được tụt xuống 0 và biến mất khỏi lịch sử.
	if old.Score != fresh.Score-cfg.MaxStalenessPenalty {
		t.Errorf("điểm = %d, muốn %d (trừ tối đa %d)",
			old.Score, fresh.Score-cfg.MaxStalenessPenalty, cfg.MaxStalenessPenalty)
	}
}

func TestScoreIsClamped(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxIndependentBonus = 100

	var ev []Evidence
	for _, id := range []string{"a", "b", "c", "d", "e", "f"} {
		ev = append(ev, Evidence{
			SourceID: id, Origin: OriginDirect,
			TrustScore: 100, Confidence: 100, LastSeen: now,
		})
	}

	if got := Evaluate(base(ev...), cfg); got.Score != 100 {
		t.Errorf("Score = %d, muốn bị chặn ở 100", got.Score)
	}
}

// Cùng bằng chứng phải cho cùng kết quả, bất kể thứ tự hàng mà CSDL trả về (xung đột
// C5). Không có tính chất này thì việc dựng lại L2 từ L1 sẽ không tái tạo được L3.
func TestEvaluateIsOrderIndependent(t *testing.T) {
	cfg := DefaultConfig()
	ev := []Evidence{strongFeed("urlhaus"), strongFeed("hagezi"), strongFeed("cert")}

	want := Evaluate(base(ev...), cfg)

	reversed := slices.Clone(ev)
	slices.Reverse(reversed)
	got := Evaluate(base(reversed...), cfg)

	if got.Action != want.Action || got.Score != want.Score ||
		got.IndependentSourceCount != want.IndependentSourceCount {
		t.Errorf("đảo thứ tự đổi kết quả: %+v vs %+v", got, want)
	}
	if !slices.Equal(got.MatchedRules, want.MatchedRules) {
		t.Errorf("MatchedRules phụ thuộc thứ tự: %v vs %v", got.MatchedRules, want.MatchedRules)
	}
}

func TestMatchedRulesAreDeduplicated(t *testing.T) {
	cfg := DefaultConfig()
	got := Evaluate(base(strongFeed("hagezi"), strongFeed("hagezi")), cfg)

	if len(got.MatchedRules) != 1 {
		t.Errorf("MatchedRules = %v, muốn đúng một mục", got.MatchedRules)
	}
	if got.IndependentSourceCount != 1 {
		t.Errorf("IndependentSourceCount = %d, muốn 1: cùng một nguồn không tự nhân đôi",
			got.IndependentSourceCount)
	}
}

func TestConfigValidate(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig không hợp lệ: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*Config)
	}{
		{"thiếu version", func(c *Config) { c.Version = "" }},
		{"action mặc định lạ", func(c *Config) { c.DefaultAction = "DROP" }},
		{"không có category", func(c *Config) { c.Categories = nil }},
		{"ngưỡng ngoài khoảng", func(c *Config) { c.Categories["malware"] = CategoryPolicy{MinScore: 150} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := DefaultConfig()
			tt.mut(&c)
			if err := c.Validate(); err == nil {
				t.Error("Validate() = nil, muốn lỗi")
			}
		})
	}
}
