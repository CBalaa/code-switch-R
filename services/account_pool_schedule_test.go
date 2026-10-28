package services

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func schedulePoolForTest(windows ...AccountPoolScheduleWindow) *ProviderPool {
	pool := validAccountPoolForTest()
	pool.ID = "schedule-test-pool"
	pool.AccountPoolConfig.Schedule = &AccountPoolSchedule{Enabled: true, Windows: windows}
	return pool
}

func scheduleTimeForTest(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.ParseInLocation("2006-01-02 15:04:05", value, beijingLocation)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestAccountPoolScheduleMinuteBoundariesAndWeeklyRollover(t *testing.T) {
	pool := schedulePoolForTest(
		AccountPoolScheduleWindow{Weekday: 1, StartTime: "18:00", EndTime: "23:59"},
		AccountPoolScheduleWindow{Weekday: 3, StartTime: "12:30", EndTime: "12:30"},
	)
	tests := []struct {
		name, now, next string
		open            bool
	}{
		{name: "before start", now: "2026-10-26 17:59:59", next: "2026-10-26 18:00:00"},
		{name: "at start", now: "2026-10-26 18:00:00", next: "2026-10-27 00:00:00", open: true},
		{name: "last second of end minute", now: "2026-10-26 23:59:59", next: "2026-10-27 00:00:00", open: true},
		{name: "at midnight closes", now: "2026-10-27 00:00:00", next: "2026-10-28 12:30:00"},
		{name: "same minute starts", now: "2026-10-28 12:30:00", next: "2026-10-28 12:31:00", open: true},
		{name: "same minute includes last second", now: "2026-10-28 12:30:59", next: "2026-10-28 12:31:00", open: true},
		{name: "same minute ends", now: "2026-10-28 12:31:00", next: "2026-11-02 18:00:00"},
		{name: "empty weekday", now: "2026-10-30 20:00:00", next: "2026-11-02 18:00:00"},
		{name: "week rollover", now: "2026-11-01 23:59:59", next: "2026-11-02 18:00:00"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := evaluateAccountPoolSchedule(pool, scheduleTimeForTest(t, test.now))
			if err != nil {
				t.Fatal(err)
			}
			if !result.Enabled || result.IsOpen != test.open || !result.NextChangeAt.Equal(scheduleTimeForTest(t, test.next)) {
				t.Fatalf("evaluation = %+v; want enabled, open=%v, next=%s", result, test.open, test.next)
			}
		})
	}
	beijingNow := scheduleTimeForTest(t, "2026-10-26 18:00:00")
	utcResult, err := evaluateAccountPoolSchedule(pool, beijingNow.UTC())
	if err != nil || !utcResult.IsOpen || !utcResult.NextChangeAt.Equal(scheduleTimeForTest(t, "2026-10-27 00:00:00")) {
		t.Fatalf("UTC input must still use Beijing clock: %+v, %v", utcResult, err)
	}
}

func TestAccountPoolScheduleUnionsAndContinuousWeekBoundary(t *testing.T) {
	pool := schedulePoolForTest(
		AccountPoolScheduleWindow{Weekday: 1, StartTime: "19:00", EndTime: "21:00"},
		AccountPoolScheduleWindow{Weekday: 1, StartTime: "18:00", EndTime: "19:00"},
		AccountPoolScheduleWindow{Weekday: 1, StartTime: "21:01", EndTime: "21:30"},
		AccountPoolScheduleWindow{Weekday: 1, StartTime: "18:00", EndTime: "19:00"},
	)
	result, err := evaluateAccountPoolSchedule(pool, scheduleTimeForTest(t, "2026-10-26 19:30:00"))
	if err != nil || !result.IsOpen || !result.NextChangeAt.Equal(scheduleTimeForTest(t, "2026-10-26 21:31:00")) {
		t.Fatalf("overlapping, adjacent and duplicate windows must form one opening: %+v, %v", result, err)
	}
	pool.AccountPoolConfig.Schedule.Windows = []AccountPoolScheduleWindow{
		{Weekday: 7, StartTime: "23:00", EndTime: "23:59"},
		{Weekday: 1, StartTime: "00:00", EndTime: "01:00"},
	}
	for _, value := range []string{"2026-11-01 23:00:00", "2026-11-01 23:59:59", "2026-11-02 00:00:00"} {
		result, err := evaluateAccountPoolSchedule(pool, scheduleTimeForTest(t, value))
		if err != nil || !result.IsOpen || !result.NextChangeAt.Equal(scheduleTimeForTest(t, "2026-11-02 01:01:00")) {
			t.Fatalf("continuous Sunday-to-Monday opening at %s = %+v, %v", value, result, err)
		}
	}
	pool.AccountPoolConfig.Schedule.Windows = nil
	for weekday := 1; weekday <= 7; weekday++ {
		pool.AccountPoolConfig.Schedule.Windows = append(pool.AccountPoolConfig.Schedule.Windows, AccountPoolScheduleWindow{Weekday: weekday, StartTime: "00:00", EndTime: "23:59"})
	}
	result, err = evaluateAccountPoolSchedule(pool, scheduleTimeForTest(t, "2026-11-01 23:59:59"))
	if err != nil || !result.IsOpen || !result.NextChangeAt.IsZero() {
		t.Fatalf("continuous full week must have no transition: %+v, %v", result, err)
	}
}

func TestAccountPoolScheduleDefaultsAndInvalidData(t *testing.T) {
	now := scheduleTimeForTest(t, "2026-10-26 18:00:00")
	pool := validAccountPoolForTest()
	for _, candidate := range []*ProviderPool{nil, {}, pool} {
		result, err := evaluateAccountPoolSchedule(candidate, now)
		if err != nil || result.Enabled || !result.IsOpen || !result.NextChangeAt.IsZero() {
			t.Fatalf("omitted schedule must remain unrestricted: %+v, %v", result, err)
		}
	}
	pool.AccountPoolConfig.Schedule = &AccountPoolSchedule{Windows: []AccountPoolScheduleWindow{{Weekday: -1}}}
	if err := checkAccountPoolScheduleOpen(pool, now); err != nil {
		t.Fatalf("disabled stale schedule must remain unrestricted: %v", err)
	}
	pool.AccountPoolConfig.Schedule.Enabled = true
	pool.PoolType = ProviderPoolTypeNormal
	if err := checkAccountPoolScheduleOpen(pool, now); err != nil {
		t.Fatalf("normal pool must ignore account schedule: %v", err)
	}

	tests := []struct {
		name    string
		windows []AccountPoolScheduleWindow
	}{
		{name: "no windows"},
		{name: "weekday zero", windows: []AccountPoolScheduleWindow{{Weekday: 0, StartTime: "00:00", EndTime: "23:59"}}},
		{name: "weekday eight", windows: []AccountPoolScheduleWindow{{Weekday: 8, StartTime: "00:00", EndTime: "23:59"}}},
		{name: "short hour", windows: []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "8:00", EndTime: "23:59"}}},
		{name: "invalid hour", windows: []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "24:00", EndTime: "23:59"}}},
		{name: "invalid minute", windows: []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "18:00", EndTime: "23:60"}}},
		{name: "crosses midnight", windows: []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "23:00", EndTime: "01:00"}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := schedulePoolForTest(test.windows...)
			result, err := evaluateAccountPoolSchedule(candidate, now)
			if err == nil || !result.Enabled || result.IsOpen || !result.NextChangeAt.IsZero() {
				t.Fatalf("invalid enabled data must fail closed: %+v, %v", result, err)
			}
			var closedErr *accountPoolScheduleClosedError
			if err := checkAccountPoolScheduleOpen(candidate, now); !errors.As(err, &closedErr) || closedErr.Cause == nil || closedErr.PoolID != candidate.ID {
				t.Fatalf("invalid data must produce typed local error: %+v, %v", closedErr, err)
			}
		})
	}
	closedPool := schedulePoolForTest(AccountPoolScheduleWindow{Weekday: 1, StartTime: "19:00", EndTime: "20:00"})
	var closedErr *accountPoolScheduleClosedError
	if err := checkAccountPoolScheduleOpen(closedPool, now); !errors.As(err, &closedErr) || closedErr.Cause != nil ||
		!closedErr.NextOpenAt.Equal(scheduleTimeForTest(t, "2026-10-26 19:00:00")) || !strings.Contains(closedErr.Error(), "北京时间") {
		t.Fatalf("closed pool error = %+v, %v", closedErr, err)
	}
}

func TestAccountPoolScheduleSaveValidationAndRoundTrip(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	service := NewProviderPoolService()
	pool := validAccountPoolForTest()
	pool.AccountPoolConfig.Schedule = &AccountPoolSchedule{Enabled: true}
	if _, err := service.SavePool(pool); err == nil {
		t.Fatal("enabled schedule without windows was saved")
	}
	pool.AccountPoolConfig.Schedule.Windows = []AccountPoolScheduleWindow{{Weekday: 4, StartTime: " 18:00 ", EndTime: "23:59"}}
	id, err := service.SavePool(pool)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := service.GetPool(id)
	if err != nil || loaded == nil || loaded.AccountPoolConfig.Schedule == nil ||
		!loaded.AccountPoolConfig.Schedule.Enabled || loaded.AccountPoolConfig.Schedule.Windows[0].StartTime != "18:00" {
		t.Fatalf("schedule round trip = %+v, %v", loaded, err)
	}
	loaded.AccountPoolConfig.Schedule.Enabled = false
	if _, err := service.SavePool(loaded); err != nil {
		t.Fatal(err)
	}
	loaded, err = service.GetPool(id)
	if err != nil || loaded.AccountPoolConfig.Schedule.Enabled || len(loaded.AccountPoolConfig.Schedule.Windows) != 1 {
		t.Fatalf("disabled schedule should preserve valid windows: %+v, %v", loaded, err)
	}
	before, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	loaded.AccountPoolConfig.Schedule.Windows[0].EndTime = "01:00"
	if _, err := service.SavePool(loaded); err == nil {
		t.Fatal("invalid disabled windows were saved")
	}
	after, err := os.ReadFile(service.path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("rejected save changed persisted configuration: %v", err)
	}
}

func TestAccountPoolScheduleStoreUpgradeAndFutureVersionRejection(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	service := NewProviderPoolService()
	if err := os.MkdirAll(filepath.Dir(service.path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(service.path), appSettingsFileName), []byte(`{"enable_first_text_retry":true,"first_text_retry_timeout_seconds":5}`), 0o600); err != nil {
		t.Fatal(err)
	}
	pool := validAccountPoolForTest()
	pool.ID = "store-schedule-pool"
	if err := AtomicWriteJSON(service.path, &providerPoolStore{Version: 5, Pools: []ProviderPool{*pool}}); err != nil {
		t.Fatal(err)
	}
	loaded, err := service.GetPool(pool.ID)
	if err != nil || !loaded.FirstTextRetryEnabled || loaded.FirstTextRetryTimeoutSeconds != 5 || loaded.AccountPoolConfig.Schedule != nil {
		t.Fatalf("v5 migration lost old retry setting: %+v, %v", loaded, err)
	}
	data, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	var store providerPoolStore
	if err := json.Unmarshal(data, &store); err != nil || store.Version != 7 {
		t.Fatalf("v5 migration must reach v7: version=%d, err=%v", store.Version, err)
	}
	pool.FirstTextRetryEnabled = false
	pool.FirstTextRetryTimeoutSeconds = 45
	if err := AtomicWriteJSON(service.path, &providerPoolStore{Version: 6, Pools: []ProviderPool{*pool}}); err != nil {
		t.Fatal(err)
	}
	loaded, err = service.GetPool(pool.ID)
	if err != nil || loaded.FirstTextRetryEnabled || loaded.FirstTextRetryTimeoutSeconds != 45 {
		t.Fatalf("v6 must not repeat v5 global-setting migration: %+v, %v", loaded, err)
	}
	if _, err := service.SavePool(loaded); err != nil {
		t.Fatal(err)
	}
	data, err = os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &store); err != nil || store.Version != 7 {
		t.Fatalf("v6 save must upgrade to v7: version=%d, err=%v", store.Version, err)
	}
	if err := AtomicWriteJSON(service.path, &providerPoolStore{Version: 8, Pools: []ProviderPool{*pool}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(service.path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GetPool(pool.ID); err == nil {
		t.Fatal("future-version store must reject reads")
	}
	if _, err := service.ResolvePoolByID(pool.ID); err == nil {
		t.Fatal("future-version store must reject relay resolution")
	}
	if _, err := service.SavePool(pool); err == nil {
		t.Fatal("future-version store must reject writes")
	}
	if err := service.DeletePool(pool.ID); err == nil {
		t.Fatal("future-version store must reject deletion")
	}
	after, err := os.ReadFile(service.path)
	if err != nil || string(before) != string(after) {
		t.Fatalf("future-version operations changed the store: %v", err)
	}
}

func TestAccountPoolScheduleStatusesAreCredentialFreeAndUserScoped(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	service := NewProviderPoolService()
	pool := validAccountPoolForTest()
	pool.ID = "same-pool-id"
	pool.AccountPoolConfig.Schedule = &AccountPoolSchedule{Enabled: true}
	for weekday := 1; weekday <= 7; weekday++ {
		pool.AccountPoolConfig.Schedule.Windows = append(pool.AccountPoolConfig.Schedule.Windows, AccountPoolScheduleWindow{Weekday: weekday, StartTime: "00:00", EndTime: "23:59"})
	}
	if _, err := service.SavePoolForUser("schedule-alice", pool); err != nil {
		t.Fatal(err)
	}
	bobPool := validChatAccountPoolForTest()
	bobPool.ID = pool.ID
	if _, err := service.SavePoolForUser("schedule-bob", bobPool); err != nil {
		t.Fatal(err)
	}
	if _, err := service.SavePoolForUser("schedule-alice", &ProviderPool{Platform: "openai-responses", Name: "ordinary", Mode: ProviderPoolModeManaged}); err != nil {
		t.Fatal(err)
	}
	result, err := service.GetAccountPoolScheduleStatusesForUser("schedule-alice", "openai-responses")
	if err != nil || len(result.Statuses) != 1 || result.Statuses[0].PoolID != pool.ID || !result.Statuses[0].Enabled || !result.Statuses[0].IsOpen {
		t.Fatalf("Alice schedule status = %+v, %v", result, err)
	}
	if _, err := time.Parse(time.RFC3339, result.ServerNow); err != nil || !strings.HasSuffix(result.ServerNow, "+08:00") {
		t.Fatalf("server clock must be RFC3339 Beijing time: %s, %v", result.ServerNow, err)
	}
	payload, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, sensitive := range []string{"apiKey", "apiUrl", pool.AccountPoolConfig.APIURL, pool.AccountPoolConfig.Keys[0].APIKey} {
		if strings.Contains(string(payload), sensitive) {
			t.Fatalf("status response exposed %q: %s", sensitive, payload)
		}
	}
	pool.AccountPoolConfig.Schedule.Windows = []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "18:00", EndTime: "19:00"}}
	if _, err := service.SavePoolForUser("schedule-alice", pool); err != nil {
		t.Fatal(err)
	}
	result, err = service.GetAccountPoolScheduleStatusesForUser("schedule-alice", "openai-responses")
	if err != nil || len(result.Statuses) != 1 {
		t.Fatalf("scheduled status = %+v, %v", result, err)
	}
	serverNow, err := time.Parse(time.RFC3339, result.ServerNow)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := evaluateAccountPoolSchedule(pool, serverNow)
	if err != nil || result.Statuses[0].IsOpen != expected.IsOpen || result.Statuses[0].NextChangeAt != expected.NextChangeAt.Format(time.RFC3339) {
		t.Fatalf("status must use its returned server clock: %+v; expected %+v, %v", result, expected, err)
	}
	result, err = service.GetAccountPoolScheduleStatusesForUser("schedule-bob", "openai-chat")
	if err != nil || len(result.Statuses) != 1 || result.Statuses[0].Enabled || !result.Statuses[0].IsOpen {
		t.Fatalf("Bob must keep his own unrestricted schedule: %+v, %v", result, err)
	}
	result, err = service.GetAccountPoolScheduleStatusesForUser("schedule-bob", "openai-responses")
	if err != nil || result.Statuses == nil || len(result.Statuses) != 0 {
		t.Fatalf("platform and user isolation returned wrong statuses: %+v, %v", result, err)
	}

	// Hand-edited invalid enabled schedules remain visibly closed.
	alice, err := NewProviderPoolServiceForUser("schedule-alice")
	if err != nil {
		t.Fatal(err)
	}
	pool.AccountPoolConfig.Schedule.Windows = nil
	if err := AtomicWriteJSON(alice.path, &providerPoolStore{Version: providerPoolsStoreVersion, Pools: []ProviderPool{*pool}}); err != nil {
		t.Fatal(err)
	}
	result, err = service.GetAccountPoolScheduleStatusesForUser("schedule-alice", "openai-responses")
	if err != nil || len(result.Statuses) != 1 || !result.Statuses[0].Enabled || result.Statuses[0].IsOpen || result.Statuses[0].NextChangeAt != "" {
		t.Fatalf("invalid persisted schedule must report closed: %+v, %v", result, err)
	}
}

func requireScheduleSignal(t *testing.T, changes <-chan struct{}, want bool) {
	t.Helper()
	select {
	case <-changes:
		if !want {
			t.Fatal("unexpected pool schedule notification")
		}
	default:
		if want {
			t.Fatal("missing pool schedule notification")
		}
	}
}

func TestAccountPoolScheduleChangeSubscriptionsIsolatePoolsAndUsers(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	service := NewProviderPoolService()
	pool := validAccountPoolForTest()
	pool.ID = "same-pool-id"
	first, cancelFirst, err := subscribeAccountPoolScheduleChanges("schedule-alice", pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelFirst()
	second, cancelSecond, err := subscribeAccountPoolScheduleChanges("schedule-alice", pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelSecond()
	otherUser, cancelOtherUser, err := subscribeAccountPoolScheduleChanges("schedule-bob", pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelOtherUser()
	otherPool, cancelOtherPool, err := subscribeAccountPoolScheduleChanges("schedule-alice", "other-pool")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelOtherPool()
	legacy, cancelLegacy, err := subscribeAccountPoolScheduleChanges("", pool.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer cancelLegacy()
	for count := 0; count < 2; count++ {
		if _, err := service.SavePoolForUser("schedule-alice", pool); err != nil {
			t.Fatal(err)
		}
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatal("rapid saves should coalesce without blocking or losing subscribers")
	}
	requireScheduleSignal(t, first, true)
	requireScheduleSignal(t, second, true)
	for _, changes := range []<-chan struct{}{otherUser, otherPool, legacy} {
		requireScheduleSignal(t, changes, false)
	}
	pool.AccountPoolConfig.Schedule = &AccountPoolSchedule{Enabled: true}
	if _, err := service.SavePoolForUser("schedule-alice", pool); err == nil {
		t.Fatal("invalid save unexpectedly succeeded")
	}
	requireScheduleSignal(t, first, false)
	cancelFirst()
	cancelFirst() // Cancellation is idempotent and does not close the channel.
	if err := service.DeletePoolForUser("schedule-alice", pool.ID); err != nil {
		t.Fatal(err)
	}
	requireScheduleSignal(t, first, false)
	requireScheduleSignal(t, second, true)
	for _, changes := range []<-chan struct{}{otherUser, otherPool, legacy} {
		requireScheduleSignal(t, changes, false)
	}
	if err := service.DeletePoolForUser("schedule-alice", pool.ID); err == nil {
		t.Fatal("deleting absent pool unexpectedly succeeded")
	}
	requireScheduleSignal(t, second, false)
	if _, _, err := subscribeAccountPoolScheduleChanges("../invalid", pool.ID); err == nil {
		t.Fatal("invalid user ID accepted for subscription")
	}
	if _, _, err := subscribeAccountPoolScheduleChanges("schedule-alice", ""); err == nil {
		t.Fatal("empty pool ID accepted for subscription")
	}
}

func TestAccountPoolScheduleChangeSubscriptionsIsolateConfigPaths(t *testing.T) {
	firstHome := t.TempDir()
	t.Setenv("HOME", firstHome)
	first, cancelFirst, err := subscribeAccountPoolScheduleChanges("schedule-alice", "same-pool-id")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelFirst()
	t.Setenv("HOME", t.TempDir())
	second, cancelSecond, err := subscribeAccountPoolScheduleChanges("schedule-alice", "same-pool-id")
	if err != nil {
		t.Fatal(err)
	}
	defer cancelSecond()
	pool := validAccountPoolForTest()
	pool.ID = "same-pool-id"
	if _, err := NewProviderPoolService().SavePoolForUser("schedule-alice", pool); err != nil {
		t.Fatal(err)
	}
	requireScheduleSignal(t, first, false)
	requireScheduleSignal(t, second, true)
	t.Setenv("HOME", firstHome)
	if _, err := NewProviderPoolService().SavePoolForUser("schedule-alice", pool); err != nil {
		t.Fatal(err)
	}
	requireScheduleSignal(t, first, true)
	requireScheduleSignal(t, second, false)
}
