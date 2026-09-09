package services

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSpecialBlacklistRuleMatchingOrderAndJSON(t *testing.T) {
	pool := &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{
		{ID: "first", Name: "First", HTTPStatus: 429},
		{ID: "second", Name: "Second", HTTPStatus: 429, JSONPath: "error.code", ExpectedJSONValue: `"limit"`},
	}}
	matched := specialBlacklistRuleForFailure(pool, 429, `{"error":{"code":"limit"}}`)
	if matched == nil || matched.ID != "first" {
		t.Fatalf("matched rule = %#v, want first rule", matched)
	}

	pool.SpecialBlacklistRules = pool.SpecialBlacklistRules[1:]
	matched = specialBlacklistRuleForFailure(pool, 429, `{"error":{"code":"limit"}}`)
	if matched == nil || matched.ID != "second" {
		t.Fatalf("matched JSON rule = %#v, want second", matched)
	}
	if matched := specialBlacklistRuleForFailure(pool, 429, `not json`); matched != nil {
		t.Fatalf("non-JSON response matched %#v", matched)
	}
	if matched := specialBlacklistRuleForFailure(pool, 429, `{"error":{"code":429}}`); matched != nil {
		t.Fatalf("different JSON type matched %#v", matched)
	}
}

func TestFirstTextTimeoutMatchesSpecialBlacklistRule(t *testing.T) {
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	attemptLogs := NewPoolAttemptLogService()
	relay.SetPoolAttemptLogService(attemptLogs)
	rule := SpecialBlacklistRule{
		ID:                "first-text-timeout",
		Name:              "First text timeout",
		HTTPStatus:        504,
		JSONPath:          "error.code",
		ExpectedJSONValue: `"first_text_timeout"`,
		Threshold:         1,
		DurationMinutes:   1,
	}
	pool := &ProviderPool{
		ID:                    "timeout-pool",
		Platform:              "openai-responses",
		Mode:                  ProviderPoolModeManaged,
		AutoBlacklistEnabled:  true,
		SpecialBlacklistRules: []SpecialBlacklistRule{rule},
	}
	provider := Provider{ID: 7, Name: "slow-provider", Enabled: true}

	if matched := specialBlacklistRuleForFailure(pool, 504, firstTextTimeoutErrorBody); matched == nil || matched.ID != rule.ID {
		t.Fatalf("first-text timeout rule match = %#v, want %q", matched, rule.ID)
	}
	if !relay.recordCodexStreamPreflightFailureForUser("user-a", pool.Platform, pool.ID, pool, provider, errCodexFirstTextTimeout) {
		t.Fatal("first-text timeout did not trigger its special blacklist rule")
	}
	entries := attemptLogs.List("user-a", 1, time.Time{})
	if len(entries) != 1 || !strings.Contains(entries[0].Message, firstTextTimeoutErrorBody) {
		t.Fatalf("first-text timeout attempt log = %#v, want JSON body", entries)
	}

	penalty := relay.poolPenalties[penaltyKey("user-a", pool.Platform, pool.ID, provider.ID)]
	if penalty == nil || penalty.RuleFailureCounts[rule.ID] != 1 || penalty.LastReason != rule.Name || time.Until(penalty.BlacklistedUntil) <= 0 {
		t.Fatalf("unexpected first-text timeout penalty: %#v", penalty)
	}
}

func TestSpecialBlacklistRuleUsesIndependentCounterAndSuccessReset(t *testing.T) {
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	provider := Provider{ID: 1, Name: "provider-a"}
	rule := SpecialBlacklistRule{ID: "rate-limit", Name: "Rate limit", HTTPStatus: 429, Threshold: 2, DurationMinutes: 1}
	pool := &ProviderPool{ID: "pool-a", Platform: "openai-chat", Mode: ProviderPoolModeManaged, AutoBlacklistEnabled: true, AutoBlacklistThreshold: 3, AutoBlacklistDurationMinutes: 10, SpecialBlacklistRules: []SpecialBlacklistRule{rule}}

	if relay.recordProviderFailureWithRuleForUser("user-a", pool.Platform, pool.ID, pool, provider, "HTTP 429", &rule) {
		t.Fatal("first special failure blacklisted provider")
	}
	penalty := relay.poolPenalties[penaltyKey("user-a", pool.Platform, pool.ID, provider.ID)]
	if penalty == nil || penalty.FailureCount != 0 || penalty.RuleFailureCounts[rule.ID] != 1 {
		t.Fatalf("unexpected independent counters: %#v", penalty)
	}
	if !relay.recordProviderFailureWithRuleForUser("user-a", pool.Platform, pool.ID, pool, provider, "HTTP 429", &rule) {
		t.Fatal("second special failure did not blacklist provider")
	}
	if penalty.LastReason != rule.Name || time.Until(penalty.BlacklistedUntil) <= 0 {
		t.Fatalf("unexpected special blacklist state: %#v", penalty)
	}

	relay.recordProviderSuccessForUser("user-a", pool.Platform, pool.ID, provider)
	if _, exists := relay.poolPenalties[penaltyKey("user-a", pool.Platform, pool.ID, provider.ID)]; exists {
		t.Fatal("success did not clear all failure counters")
	}

	relay.recordProviderFailureWithRuleForUser("user-a", pool.Platform, pool.ID, pool, provider, "HTTP 500", nil)
	penalty = relay.poolPenalties[penaltyKey("user-a", pool.Platform, pool.ID, provider.ID)]
	if penalty == nil || penalty.FailureCount != 1 || len(penalty.RuleFailureCounts) != 0 {
		t.Fatalf("global fallback did not use global counter: %#v", penalty)
	}
}

func TestSpecialBlacklistRuleValidation(t *testing.T) {
	pool := &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{{Name: "bad", HTTPStatus: 429, JSONPath: "error.code", ExpectedJSONValue: "not-json", Threshold: 1, DurationMinutes: 1}}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err == nil {
		t.Fatal("invalid JSON value was accepted")
	}
	pool.SpecialBlacklistRules = []SpecialBlacklistRule{{Name: "good", HTTPStatus: 429, JSONPath: "error.code", ExpectedJSONValue: `"limit"`, Threshold: 1, DurationMinutes: 1}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("valid rule rejected: %v", err)
	}
	if !strings.HasPrefix(pool.SpecialBlacklistRules[0].ID, "rule_") {
		t.Fatalf("rule id was not generated: %q", pool.SpecialBlacklistRules[0].ID)
	}

	pool.SpecialBlacklistRules[0].DurationMinutes = maxSpecialBlacklistDurationMinutes
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("maximum special blacklist duration was rejected: %v", err)
	}
	pool.SpecialBlacklistRules[0].DurationMinutes = maxSpecialBlacklistDurationMinutes + 1
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err == nil {
		t.Fatal("special blacklist duration above maximum was accepted")
	}
}

func intPtr(v int) *int { return &v }

func TestSpecialBlacklistRuleUntilModeValidation(t *testing.T) {
	valid := SpecialBlacklistRule{Name: "until", HTTPStatus: 429, Threshold: 1, DurationType: SpecialBlacklistDurationTypeUntil, UntilDayOffset: intPtr(1), UntilTime: "00:00"}

	pool := &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{valid}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("valid until rule rejected: %v", err)
	}
	if got := pool.SpecialBlacklistRules[0].DurationType; got != SpecialBlacklistDurationTypeUntil {
		t.Fatalf("until rule type = %q, want %q", got, SpecialBlacklistDurationTypeUntil)
	}

	// A missing offset is as invalid as an out-of-range one.
	for _, offset := range []*int{nil, intPtr(-1), intPtr(maxSpecialBlacklistUntilDayOffset + 1)} {
		rule := valid
		rule.UntilDayOffset = offset
		pool := &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
		if err := normalizeAndValidateSpecialBlacklistRules(pool); err == nil {
			t.Fatalf("until day offset %v was accepted", offset)
		}
	}

	// Offset 0 (= today) is a legitimate value and must survive validation.
	rule := valid
	rule.UntilDayOffset = intPtr(0)
	pool = &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("until day offset 0 rejected: %v", err)
	}

	for _, badTime := range []string{"", "24:00", "12:60", "9:30", "0900", "abc"} {
		rule := valid
		rule.UntilTime = badTime
		pool := &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
		if err := normalizeAndValidateSpecialBlacklistRules(pool); err == nil {
			t.Fatalf("until time %q was accepted", badTime)
		}
	}

	rule = valid
	rule.DurationType = "weekly"
	pool = &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err == nil {
		t.Fatal("unknown duration type was accepted")
	}

	// Duration-mode rules (including legacy empty type) keep working and lose
	// any stale until fields. Type matching is case-insensitive and trimmed.
	rule = valid
	rule.DurationType = "  "
	rule.DurationMinutes = 5
	pool = &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("legacy duration rule rejected: %v", err)
	}
	normalized := pool.SpecialBlacklistRules[0]
	if normalized.DurationType != SpecialBlacklistDurationTypeDuration || normalized.UntilDayOffset != nil || normalized.UntilTime != "" {
		t.Fatalf("duration rule kept stale until fields: %+v", normalized)
	}

	rule = valid
	rule.DurationType = " UNTIL "
	pool = &ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}
	if err := normalizeAndValidateSpecialBlacklistRules(pool); err != nil {
		t.Fatalf("case-insensitive until type rejected: %v", err)
	}
}

func TestSpecialBlacklistUntilDayOffsetZeroRoundTrip(t *testing.T) {
	rule := SpecialBlacklistRule{
		Name:           "same-day",
		HTTPStatus:     429,
		Threshold:      1,
		DurationType:   SpecialBlacklistDurationTypeUntil,
		UntilDayOffset: intPtr(0),
		UntilTime:      "23:59",
	}
	if err := normalizeAndValidateSpecialBlacklistRules(&ProviderPool{SpecialBlacklistRules: []SpecialBlacklistRule{rule}}); err != nil {
		t.Fatalf("valid until rule rejected: %v", err)
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatalf("marshal rule: %v", err)
	}
	if !strings.Contains(string(data), `"untilDayOffset":0`) {
		t.Fatalf("day offset 0 was omitted from JSON: %s", data)
	}
	var back SpecialBlacklistRule
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal rule: %v", err)
	}
	if back.UntilDayOffset == nil || *back.UntilDayOffset != 0 {
		t.Fatalf("day offset 0 did not survive the JSON round trip: %+v", back)
	}
}

func TestSpecialBlacklistDeadline(t *testing.T) {
	// Production servers may run far from Beijing (the ld host uses
	// US/Eastern); "until" targets must still resolve on the Beijing clock.
	newYork := time.FixedZone("EDT", -4*60*60)
	now := time.Date(2026, 8, 31, 10, 30, 15, 0, newYork) // 22:30 Beijing

	if got := specialBlacklistDeadline(now, nil, 5); !got.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("nil rule deadline = %v, want %v", got, now.Add(5*time.Minute))
	}
	durationRule := &SpecialBlacklistRule{Name: "fixed", Threshold: 1, DurationMinutes: 7}
	if got := specialBlacklistDeadline(now, durationRule, 7); !got.Equal(now.Add(7 * time.Minute)) {
		t.Fatalf("duration rule deadline = %v, want %v", got, now.Add(7*time.Minute))
	}

	untilRule := &SpecialBlacklistRule{Name: "until", Threshold: 1, DurationType: SpecialBlacklistDurationTypeUntil}
	untilRule.UntilDayOffset, untilRule.UntilTime = intPtr(0), "23:59"
	want := time.Date(2026, 8, 31, 23, 59, 0, 0, beijingLocation)
	if got := specialBlacklistDeadline(now, untilRule, 7); !got.Equal(want) {
		t.Fatalf("same-day until deadline = %v, want %v", got, want)
	}

	untilRule.UntilDayOffset, untilRule.UntilTime = intPtr(1), "00:00"
	want = time.Date(2026, 9, 1, 0, 0, 0, 0, beijingLocation)
	if got := specialBlacklistDeadline(now, untilRule, 7); !got.Equal(want) {
		t.Fatalf("next-day until deadline = %v, want %v", got, want)
	}

	// Regression for the ld deployment: a 23:10 Beijing trigger with a
	// "next day 00:00" rule must block until Beijing midnight (~50 minutes),
	// not until the US East Coast midnight (Beijing noon, ~770 minutes).
	// The trigger instant must land on the same deadline whichever clock it
	// is expressed in.
	trigger := time.Date(2026, 9, 8, 23, 10, 0, 0, beijingLocation)
	want = time.Date(2026, 9, 9, 0, 0, 0, 0, beijingLocation)
	if got := specialBlacklistDeadline(trigger, untilRule, 7); !got.Equal(want) {
		t.Fatalf("beijing-clock deadline = %v, want %v", got, want)
	}
	if got := specialBlacklistDeadline(trigger.In(newYork), untilRule, 7); !got.Equal(want) {
		t.Fatalf("server-clock deadline = %v, want %v", got, want)
	}
	if remaining := want.Sub(trigger); remaining < 49*time.Minute || remaining > 51*time.Minute {
		t.Fatalf("regression deadline drift = %v, want ~50 minutes", remaining)
	}

	// A future target inside the next minute is still honored exactly; only
	// targets at or before the trigger moment fall back to one minute.
	lateTrigger := time.Date(2026, 8, 31, 23, 59, 30, 0, beijingLocation)
	want = time.Date(2026, 9, 1, 0, 0, 0, 0, beijingLocation)
	if got := specialBlacklistDeadline(lateTrigger, untilRule, 7); !got.Equal(want) {
		t.Fatalf("near-future until deadline = %v, want %v", got, want)
	}

	// A target that already passed still blacklists briefly instead of no-oping.
	untilRule.UntilDayOffset, untilRule.UntilTime = intPtr(0), "00:00"
	if got := specialBlacklistDeadline(now, untilRule, 7); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("past until deadline = %v, want %v", got, now.Add(time.Minute))
	}

	// Stale unparseable times degrade to 00:00 and clamp the same way.
	untilRule.UntilDayOffset, untilRule.UntilTime = intPtr(0), "stale"
	if got := specialBlacklistDeadline(now, untilRule, 7); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("stale until time deadline = %v, want %v", got, now.Add(time.Minute))
	}

	// Stale nil offsets degrade to today; type matching stays lenient, so a
	// hand-edited " UNTIL " type still computes an until deadline (now+7m would
	// mean it fell back to the duration branch).
	staleType := &SpecialBlacklistRule{Name: "stale-type", Threshold: 1, DurationType: " UNTIL ", UntilTime: "23:59"}
	want = time.Date(2026, 8, 31, 23, 59, 0, 0, beijingLocation)
	if got := specialBlacklistDeadline(now, staleType, 7); !got.Equal(want) {
		t.Fatalf("stale-type until deadline = %v, want %v", got, want)
	}
	if got := specialBlacklistDeadline(now, nil, 7); !got.Equal(now.Add(7 * time.Minute)) {
		t.Fatalf("duration fallback changed: %v", got)
	}
}

func TestSpecialBlacklistUntilRuleRecordsTargetDeadline(t *testing.T) {
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	pool := &ProviderPool{
		ID:                           "pool-until",
		Platform:                     "openai-chat",
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistDurationMinutes: 10,
		SpecialBlacklistRules:        []SpecialBlacklistRule{},
	}
	provider := Provider{ID: 4, Name: "provider-until"}

	// Capture the baseline before triggering: the relay derives the deadline
	// from its own clock on the Beijing calendar, and if the trigger races
	// across Beijing midnight the deadline lands on the following day, so
	// accept either expected midnight.
	baseline := time.Now().In(beijingLocation)
	nextMidnight := &SpecialBlacklistRule{ID: "daily-quota", Name: "Daily quota", HTTPStatus: 429, Threshold: 1, DurationType: SpecialBlacklistDurationTypeUntil, UntilDayOffset: intPtr(1), UntilTime: "00:00"}
	if !relay.recordProviderFailureWithRuleForUser("user-a", pool.Platform, pool.ID, pool, provider, "HTTP 429", nextMidnight) {
		t.Fatal("until-mode rule did not blacklist provider")
	}
	penalty := relay.poolPenalties[penaltyKey("user-a", pool.Platform, pool.ID, provider.ID)]
	if penalty == nil || time.Until(penalty.BlacklistedUntil) <= 0 {
		t.Fatalf("unexpected until-mode penalty: %#v", penalty)
	}
	midnights := []time.Time{
		time.Date(baseline.Year(), baseline.Month(), baseline.Day(), 0, 0, 0, 0, beijingLocation).AddDate(0, 0, 1),
		time.Date(baseline.Year(), baseline.Month(), baseline.Day(), 0, 0, 0, 0, beijingLocation).AddDate(0, 0, 2),
	}
	if !nearTime(penalty.BlacklistedUntil, midnights, 2*time.Second) {
		t.Fatalf("until-mode deadline = %v, want one of %v", penalty.BlacklistedUntil, midnights)
	}

	pastTarget := &SpecialBlacklistRule{ID: "already-passed", Name: "Already passed", HTTPStatus: 429, Threshold: 1, DurationType: SpecialBlacklistDurationTypeUntil, UntilDayOffset: intPtr(0), UntilTime: "00:00"}
	if !relay.recordProviderFailureWithRuleForUser("user-b", pool.Platform, pool.ID, pool, provider, "HTTP 429", pastTarget) {
		t.Fatal("past-target until rule did not blacklist provider")
	}
	penalty = relay.poolPenalties[penaltyKey("user-b", pool.Platform, pool.ID, provider.ID)]
	if penalty == nil {
		t.Fatal("past-target penalty missing")
	}
	if remaining := time.Until(penalty.BlacklistedUntil); remaining < 55*time.Second || remaining > 65*time.Second {
		t.Fatalf("past-target deadline = %v, want ~1 minute from now", penalty.BlacklistedUntil)
	}
}

func nearTime(got time.Time, candidates []time.Time, tolerance time.Duration) bool {
	for _, candidate := range candidates {
		diff := got.Sub(candidate)
		if diff < 0 {
			diff = -diff
		}
		if diff <= tolerance {
			return true
		}
	}
	return false
}

// TestSpecialBlacklistRuleUntilModePersistsThroughSavePool exercises the real
// SavePool validation plus the on-disk JSON round trip through a fresh service
// instance, covering what plain json.Marshal tests cannot see.
func TestSpecialBlacklistRuleUntilModePersistsThroughSavePool(t *testing.T) {
	testHome := t.TempDir()
	t.Setenv("HOME", testHome)

	service := NewProviderPoolService()
	pool := &ProviderPool{
		Platform:                     "openai-chat",
		Name:                         "Until Round Trip",
		PoolType:                     ProviderPoolTypeNormal,
		Mode:                         ProviderPoolModeManaged,
		Members:                      []ProviderPoolMember{},
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       3,
		AutoBlacklistDurationMinutes: 10,
		SpecialBlacklistRules: []SpecialBlacklistRule{
			// Hand-edited style: lenient type variant, legitimate offset 0.
			{Name: "same-day", HTTPStatus: 429, Threshold: 1, DurationType: " UNTIL ", UntilDayOffset: intPtr(0), UntilTime: "23:59"},
			{Name: "fixed", HTTPStatus: 500, Threshold: 2, DurationMinutes: 15, DurationType: SpecialBlacklistDurationTypeDuration, UntilDayOffset: intPtr(3), UntilTime: "08:00"},
		},
	}
	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatalf("SavePool failed: %v", err)
	}

	reloaded := NewProviderPoolService()
	saved, err := reloaded.GetPool(id)
	if err != nil {
		t.Fatalf("GetPool failed: %v", err)
	}
	if len(saved.SpecialBlacklistRules) != 2 {
		t.Fatalf("saved rules = %+v", saved.SpecialBlacklistRules)
	}

	until := saved.SpecialBlacklistRules[0]
	if until.DurationType != SpecialBlacklistDurationTypeUntil {
		t.Fatalf("lenient type variant not normalized: %+v", until)
	}
	if until.UntilDayOffset == nil || *until.UntilDayOffset != 0 {
		t.Fatalf("day offset 0 did not survive persistence: %+v", until)
	}
	if until.UntilTime != "23:59" {
		t.Fatalf("until time not persisted: %+v", until)
	}

	fixed := saved.SpecialBlacklistRules[1]
	if fixed.DurationType != SpecialBlacklistDurationTypeDuration || fixed.UntilDayOffset != nil || fixed.UntilTime != "" {
		t.Fatalf("duration rule kept stale until fields after persistence: %+v", fixed)
	}
}

func TestPoolAttemptLogsAreUserScopedAndRedactAccountKeys(t *testing.T) {
	logs := NewPoolAttemptLogService()
	relay := NewProviderRelayService(NewProviderService(), NewProviderPoolService(), nil, nil, nil, DefaultRelayBindAddr)
	relay.SetPoolAttemptLogService(logs)
	pool := &ProviderPool{ID: "pool-a", Name: "Accounts"}
	provider := Provider{ID: -1, APIKey: "secret-key-9876"}
	rule := &SpecialBlacklistRule{Name: "Rate limit"}
	relay.recordPoolAttemptError("user-a", pool, provider, 429, rule, "upstream rejected secret-key-9876")

	entries := logs.List("user-a", 10, time.Time{})
	if len(entries) != 1 || !strings.Contains(entries[0].Message, "****9876") || !strings.Contains(entries[0].Message, "rule=Rate limit") {
		t.Fatalf("unexpected attempt entry: %#v", entries)
	}
	if strings.Contains(entries[0].Message, provider.APIKey) {
		t.Fatalf("attempt entry leaked account key: %q", entries[0].Message)
	}
	if got := logs.List("user-b", 10, time.Time{}); len(got) != 0 {
		t.Fatalf("other user received attempt logs: %#v", got)
	}
	if got := logs.List("user-a", 10, time.Now()); len(got) != 0 {
		t.Fatalf("clear cutoff did not filter prior logs: %#v", got)
	}
}
