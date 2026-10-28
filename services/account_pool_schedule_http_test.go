package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A Monday in Beijing keeps these tests independent of the machine's timezone
// and wall clock. Atomic updates also let the upstream advance the relay clock.
func accountScheduleHTTPClock(hour, minute, second int) (*atomic.Int64, func() time.Time) {
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, time.November, 2, hour, minute, second, 0, beijingLocation).UnixNano())
	return clock, func() time.Time { return time.Unix(0, clock.Load()) }
}

func accountScheduleHTTPPool(platform, upstream string, schedule *AccountPoolSchedule) *ProviderPool {
	return &ProviderPool{
		Platform:                     platform,
		Name:                         "Scheduled Account Pool",
		PoolType:                     ProviderPoolTypeAccount,
		Mode:                         ProviderPoolModeManaged,
		AutoBlacklistEnabled:         true,
		AutoBlacklistThreshold:       2,
		AutoBlacklistDurationMinutes: 10,
		AccountPoolConfig: &AccountPoolConfig{
			APIURL:            upstream,
			ResponsesEndpoint: "/v1/responses",
			ChatEndpoint:      "/v1/chat/completions",
			Keys:              []AccountPoolKey{{APIKey: "schedule-test-first"}, {APIKey: "schedule-test-second"}},
			Schedule:          schedule,
		},
	}
}

func accountScheduleHTTPEvening() *AccountPoolSchedule {
	return &AccountPoolSchedule{
		Enabled: true,
		Windows: []AccountPoolScheduleWindow{{Weekday: 1, StartTime: "18:00", EndTime: "23:59"}},
	}
}

func accountScheduleHTTPRequest(router *gin.Engine, key, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+key)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

func assertAccountScheduleHTTPClosed(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("closed pool status = %d, want 503: %s", w.Code, w.Body.String())
	}
	var result struct {
		Error string `json:"error"`
		Code  string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("decode closed pool error: %v: %s", err, w.Body.String())
	}
	if result.Code != "account_pool_closed" || result.Error == "" {
		t.Fatalf("closed pool error = %+v, want account_pool_closed with message", result)
	}
}

func accountScheduleHTTPWriteSuccess(w http.ResponseWriter, platform string) {
	w.Header().Set("Content-Type", "application/json")
	if platform == "openai-chat" {
		_, _ = w.Write([]byte(chatCompletionBody("chatcmpl_schedule", "scheduled-success")))
		return
	}
	_, _ = w.Write([]byte(`{"id":"resp_schedule","object":"response","output":[{"type":"message","content":[{"type":"output_text","text":"scheduled-success"}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}`))
}

func TestHTTPAccountPoolScheduleClosedRejectsAllRoutesWithoutFailures(t *testing.T) {
	for _, platform := range []string{"openai-responses", "openai-chat"} {
		t.Run(platform, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				accountScheduleHTTPWriteSuccess(w, platform)
			}))
			defer upstream.Close()
			relay, router, key, poolID := setupProviderPoolHTTPTest(t, platform, nil, accountScheduleHTTPPool(platform, upstream.URL, accountScheduleHTTPEvening()))
			_, relay.scheduleNow = accountScheduleHTTPClock(17, 59, 59)
			paths := []string{"/responses", "/v1/responses"}
			body := `{"model":"gpt-5","input":"hello","stream":false}`
			if platform == "openai-chat" {
				paths = []string{"/chat/completions", "/v1/chat/completions"}
				body = `{"model":"gpt-5","messages":[{"role":"user","content":"hello"}],"stream":false}`
			}
			for _, path := range paths {
				assertAccountScheduleHTTPClosed(t, accountScheduleHTTPRequest(router, key, http.MethodPost, path, body))
			}
			for _, path := range []string{"/v1/models", "/models"} {
				assertAccountScheduleHTTPClosed(t, accountScheduleHTTPRequest(router, key, http.MethodGet, path, ""))
			}
			if hits.Load() != 0 {
				t.Fatalf("closed pool made %d upstream requests", hits.Load())
			}
			if statuses := relay.ListProviderBlacklistStatus(platform, poolID); len(statuses) != 0 {
				t.Fatalf("schedule rejection blacklisted account keys: %+v", statuses)
			}
			relay.poolPenaltyMu.Lock()
			defer relay.poolPenaltyMu.Unlock()
			for _, penalty := range relay.poolPenalties {
				if penalty.FailureCount != 0 || len(penalty.RuleFailureCounts) != 0 {
					t.Fatalf("schedule rejection incremented account failures: %+v", penalty)
				}
			}
		})
	}
}

func TestHTTPAccountPoolScheduleEndMinuteAndCompatibility(t *testing.T) {
	for _, tc := range []struct {
		name     string
		schedule *AccountPoolSchedule
		hour     int
		minute   int
		second   int
		open     bool
	}{
		{"start-inclusive", accountScheduleHTTPEvening(), 18, 0, 0, true},
		{"end-minute-inclusive", accountScheduleHTTPEvening(), 23, 59, 59, true},
		{"next-day-closed", accountScheduleHTTPEvening(), 24, 0, 0, false},
		{"old-config-unrestricted", nil, 12, 0, 0, true},
		{"disabled-unrestricted", &AccountPoolSchedule{Enabled: false, Windows: accountScheduleHTTPEvening().Windows}, 12, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				accountScheduleHTTPWriteSuccess(w, "openai-chat")
			}))
			defer upstream.Close()
			relay, router, key, _ := setupProviderPoolHTTPTest(t, "openai-chat", nil, accountScheduleHTTPPool("openai-chat", upstream.URL, tc.schedule))
			_, relay.scheduleNow = accountScheduleHTTPClock(tc.hour, tc.minute, tc.second)
			w := accountScheduleHTTPRequest(router, key, http.MethodPost, "/chat/completions", `{"model":"gpt-5","messages":[],"stream":false}`)
			if !tc.open {
				assertAccountScheduleHTTPClosed(t, w)
				if hits.Load() != 0 {
					t.Fatalf("closed pool made %d upstream requests", hits.Load())
				}
				return
			}
			if w.Code != http.StatusOK || hits.Load() != 1 {
				t.Fatalf("open pool status=%d upstream hits=%d: %s", w.Code, hits.Load(), w.Body.String())
			}
		})
	}
}

func TestHTTPAccountPoolScheduleDoesNotRestrictNormalPool(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accountScheduleHTTPWriteSuccess(w, "openai-chat")
	}))
	defer upstream.Close()
	providers := []Provider{{ID: 1, Name: "normal-provider", Enabled: true, APIURL: upstream.URL, APIKey: "normal-test-key"}}
	pool := &ProviderPool{
		Platform: "openai-chat", Name: "Normal Pool", Mode: ProviderPoolModeManaged,
		Members: []ProviderPoolMember{{ProviderID: 1, Enabled: true}},
	}
	relay, router, key, _ := setupProviderPoolHTTPTest(t, "openai-chat", providers, pool)
	_, relay.scheduleNow = accountScheduleHTTPClock(12, 0, 0)
	w := accountScheduleHTTPRequest(router, key, http.MethodPost, "/chat/completions", `{"model":"gpt-5","messages":[],"stream":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("normal pool status = %d, want 200: %s", w.Code, w.Body.String())
	}
}

func TestHTTPAccountPoolScheduleModelsFallsBackToOpenBinding(t *testing.T) {
	var closedHits, openHits atomic.Int32
	closedUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		closedHits.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer closedUpstream.Close()
	openUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		openHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"open-model","object":"model"}]}`))
	}))
	defer openUpstream.Close()
	relay, router, key, _ := setupProviderPoolHTTPTest(t, "openai-responses", nil, accountScheduleHTTPPool("openai-responses", closedUpstream.URL, accountScheduleHTTPEvening()))
	_, relay.scheduleNow = accountScheduleHTTPClock(12, 0, 0)
	openPoolID, err := relay.poolService.SavePool(accountScheduleHTTPPool("openai-chat", openUpstream.URL, nil))
	if err != nil {
		t.Fatalf("save open fallback pool: %v", err)
	}
	match, err := relay.codexRelayKeys.ValidateKeyMatch(key)
	if err != nil || match == nil {
		t.Fatalf("find test relay key: match=%v err=%v", match, err)
	}
	if err := relay.codexRelayKeys.SetPoolBinding(match.ID, "openai-chat", openPoolID); err != nil {
		t.Fatalf("bind open fallback pool: %v", err)
	}
	w := accountScheduleHTTPRequest(router, key, http.MethodGet, "/v1/models", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "open-model") {
		t.Fatalf("models should use open binding, got %d: %s", w.Code, w.Body.String())
	}
	if closedHits.Load() != 0 || openHits.Load() != 1 {
		t.Fatalf("models upstream hits = closed %d open %d, want 0 and 1", closedHits.Load(), openHits.Load())
	}
}

func TestHTTPAccountPoolScheduleStopsRetryAfterClosing(t *testing.T) {
	for _, target := range []struct {
		platform, method, path, body string
		status                       int
	}{
		{"openai-responses", http.MethodPost, "/responses", `{"model":"gpt-5","input":"hello","stream":false}`, http.StatusTooManyRequests},
		{"openai-chat", http.MethodPost, "/chat/completions", `{"model":"gpt-5","messages":[],"stream":false}`, http.StatusTooManyRequests},
		{"openai-responses", http.MethodGet, "/v1/models", "", http.StatusTooManyRequests},
		{"openai-responses", http.MethodPost, "/responses", `{"model":"gpt-5","input":"hello","stream":false}`, http.StatusInternalServerError},
		{"openai-chat", http.MethodPost, "/chat/completions", `{"model":"gpt-5","messages":[],"stream":false}`, http.StatusInternalServerError},
	} {
		t.Run(fmt.Sprintf("%s%s/status=%d", target.platform, target.path, target.status), func(t *testing.T) {
			clock, now := accountScheduleHTTPClock(23, 59, 59)
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				clock.Store(time.Date(2026, time.November, 3, 0, 0, 0, 0, beijingLocation).UnixNano())
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(target.status)
				_, _ = w.Write([]byte(`{"error":{"message":"retryable rate limit"}}`))
			}))
			defer upstream.Close()
			relay, router, key, poolID := setupProviderPoolHTTPTest(t, target.platform, nil, accountScheduleHTTPPool(target.platform, upstream.URL, accountScheduleHTTPEvening()))
			relay.scheduleNow = now
			w := accountScheduleHTTPRequest(router, key, target.method, target.path, target.body)
			assertAccountScheduleHTTPClosed(t, w)
			if hits.Load() != 1 {
				t.Fatalf("retry crossed closing boundary: upstream hits=%d, want 1", hits.Load())
			}
			if statuses := relay.ListProviderBlacklistStatus(target.platform, poolID); len(statuses) != 0 {
				t.Fatalf("schedule rejection retried until account blacklist: %+v", statuses)
			}
			relay.poolPenaltyMu.Lock()
			failureCount := 0
			for _, penalty := range relay.poolPenalties {
				failureCount += penalty.FailureCount
			}
			relay.poolPenaltyMu.Unlock()
			if failureCount != 1 {
				t.Fatalf("real upstream failure before closure counted %d times, want 1", failureCount)
			}
		})
	}
}

func TestHTTPAccountPoolScheduleStopsModelsProxyTransportRetryAfterClosing(t *testing.T) {
	clock, now := accountScheduleHTTPClock(23, 59, 59)
	pool := accountScheduleHTTPPool("openai-responses", "https://schedule-test.invalid", accountScheduleHTTPEvening())
	relay, router, key, poolID := setupProviderPoolHTTPTest(t, "openai-responses", nil, pool)
	relay.scheduleNow = now
	relay.proxyManager = NewProxyManager(nil)
	var attempts atomic.Int32
	relay.httpClient = &http.Client{Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		attempts.Add(1)
		clock.Store(time.Date(2026, time.November, 3, 0, 0, 0, 0, beijingLocation).UnixNano())
		return nil, &proxyRequestError{PoolKey: "schedule-test-proxy", Err: fmt.Errorf("test proxy connection lost")}
	})}
	w := accountScheduleHTTPRequest(router, key, http.MethodGet, "/v1/models", "")
	assertAccountScheduleHTTPClosed(t, w)
	if attempts.Load() != 1 {
		t.Fatalf("models transport retry crossed closing boundary: %d attempts", attempts.Load())
	}
	if statuses := relay.ListProviderBlacklistStatus("openai-responses", poolID); len(statuses) != 0 {
		t.Fatalf("denied models transport retry blacklisted account: %+v", statuses)
	}
	relay.poolPenaltyMu.Lock()
	defer relay.poolPenaltyMu.Unlock()
	for _, penalty := range relay.poolPenalties {
		if penalty.FailureCount != 0 {
			t.Fatalf("proxy transport failure was counted against account: %+v", penalty)
		}
	}
}

func TestHTTPAccountPoolScheduleInFlightRequestsFinishAfterClosing(t *testing.T) {
	for _, platform := range []string{"openai-responses", "openai-chat"} {
		for _, stream := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stream=%t", platform, stream), func(t *testing.T) {
				clock, now := accountScheduleHTTPClock(23, 59, 59)
				started := make(chan struct{})
				release := make(chan struct{})
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if stream {
						w.Header().Set("Content-Type", "text/event-stream")
						if platform == "openai-chat" {
							_, _ = w.Write([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"scheduled-success\"}}]}\n\n"))
						} else {
							_, _ = w.Write([]byte("data: {\"type\":\"response.output_text.delta\",\"delta\":\"scheduled-success\"}\n\n"))
						}
						w.(http.Flusher).Flush()
					}
					close(started)
					select {
					case <-release:
					case <-r.Context().Done():
						return
					}
					if stream {
						if platform == "openai-responses" {
							_, _ = w.Write([]byte("data: {\"type\":\"response.completed\",\"response\":{\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n"))
						}
						_, _ = w.Write([]byte("data: [DONE]\n\n"))
						return
					}
					accountScheduleHTTPWriteSuccess(w, platform)
				}))
				defer upstream.Close()
				relay, router, key, _ := setupProviderPoolHTTPTest(t, platform, nil, accountScheduleHTTPPool(platform, upstream.URL, accountScheduleHTTPEvening()))
				relay.scheduleNow = now
				path := "/responses"
				body := fmt.Sprintf(`{"model":"gpt-5","input":"hello","stream":%t}`, stream)
				if platform == "openai-chat" {
					path = "/chat/completions"
					body = fmt.Sprintf(`{"model":"gpt-5","messages":[],"stream":%t}`, stream)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)).WithContext(ctx)
				req.Header.Set("Authorization", "Bearer "+key)
				req.Header.Set("Content-Type", "application/json")
				w := httptest.NewRecorder()
				done := make(chan struct{})
				go func() {
					router.ServeHTTP(w, req)
					close(done)
				}()
				select {
				case <-started:
				case <-ctx.Done():
					t.Fatal("upstream request did not start")
				}
				clock.Store(time.Date(2026, time.November, 3, 0, 0, 0, 0, beijingLocation).UnixNano())
				close(release)
				select {
				case <-done:
				case <-ctx.Done():
					t.Fatal("in-flight request did not finish after pool closed")
				}
				if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "scheduled-success") {
					t.Fatalf("in-flight request interrupted: %d %s", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestHTTPAccountPoolScheduleQueuedRequestsWakeAtBoundaryAndOnSave(t *testing.T) {
	type queueTimer struct {
		duration time.Duration
		fire     chan time.Time
		stopped  atomic.Bool
	}
	for _, scenario := range []string{"closing-boundary", "saved-plan-closes-pool", "saved-plan-extends-window"} {
		t.Run(scenario, func(t *testing.T) {
			oldTracker := defaultActiveRequestTracker
			defaultActiveRequestTracker = newActiveRequestTracker()
			t.Cleanup(func() { defaultActiveRequestTracker = oldTracker })
			clock, now := accountScheduleHTTPClock(18, 0, 30)
			var hits atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				accountScheduleHTTPWriteSuccess(w, "openai-chat")
			}))
			defer upstream.Close()
			pool := accountScheduleHTTPPool("openai-chat", upstream.URL, accountScheduleHTTPEvening())
			pool.AccountPoolConfig.Keys = pool.AccountPoolConfig.Keys[:1]
			if scenario == "saved-plan-extends-window" {
				pool.AccountPoolConfig.Schedule.Windows[0].EndTime = "18:00"
			}
			relay, router, key, poolID := setupProviderPoolHTTPTest(t, "openai-chat", nil, pool)
			relay.scheduleNow = now
			timers := make(chan *queueTimer, 8)
			relay.scheduleAfter = func(duration time.Duration) (<-chan time.Time, func()) {
				timer := &queueTimer{duration: duration, fire: make(chan time.Time, 1)}
				timers <- timer
				return timer.fire, func() { timer.stopped.Store(true) }
			}
			savedPool, err := relay.poolService.ResolvePoolByID(poolID)
			if err != nil || savedPool == nil {
				t.Fatalf("resolve saved pool: pool=%v err=%v", savedPool, err)
			}
			providers, err := relay.selectProvidersForRequest("openai-chat", savedPool, "gpt-5")
			if err != nil || len(providers) != 1 {
				t.Fatalf("select account to saturate: providers=%v err=%v", providers, err)
			}
			// Account keys use the shared default limit. Fill it directly so this
			// test exercises the real queue without spawning 99,999 HTTP calls.
			concurrencyKey := providerConcurrencyKey("", "openai-chat", providers[0].ID)
			relay.concurrencyLimiter.mu.Lock()
			relay.concurrencyLimiter.inFlight[concurrencyKey] = providers[0].NormalizedMaxConcurrency()
			relay.concurrencyLimiter.mu.Unlock()
			defer func() {
				relay.concurrencyLimiter.mu.Lock()
				delete(relay.concurrencyLimiter.inFlight, concurrencyKey)
				relay.concurrencyLimiter.mu.Unlock()
			}()
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			req := httptest.NewRequest(http.MethodPost, "/chat/completions", strings.NewReader(`{"model":"gpt-5","messages":[],"stream":false}`)).WithContext(ctx)
			req.Header.Set("Authorization", "Bearer "+key)
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			done := make(chan struct{})
			go func() {
				router.ServeHTTP(w, req)
				close(done)
			}()
			defer func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("queued request did not stop during cleanup")
				}
			}()
			awaitTimer := func() *queueTimer {
				t.Helper()
				select {
				case timer := <-timers:
					return timer
				case <-ctx.Done():
					t.Fatal("queued request did not register closing timer")
					return nil
				}
			}
			initialTimer := awaitTimer()
			queued := waitForActiveLog(t, "openai-chat", func(entry ReqeustLog) bool {
				return entry.QueueKey == providerQueueKey("", "openai-chat", poolID) && entry.Status == requestLogStatusQueued && entry.QueuePosition == 1
			})
			switch scenario {
			case "closing-boundary":
				if initialTimer.duration != 5*time.Hour+59*time.Minute+30*time.Second {
					t.Fatalf("closing timer duration = %v", initialTimer.duration)
				}
				clock.Store(time.Date(2026, time.November, 3, 0, 0, 0, 0, beijingLocation).UnixNano())
				initialTimer.fire <- now()
			case "saved-plan-closes-pool":
				savedPool.AccountPoolConfig.Schedule.Windows[0].StartTime = "19:00"
				if _, err := relay.poolService.SavePool(savedPool); err != nil {
					t.Fatalf("save plan that closes queued pool: %v", err)
				}
			case "saved-plan-extends-window":
				if initialTimer.duration != 30*time.Second {
					t.Fatalf("initial closing timer duration = %v, want 30s", initialTimer.duration)
				}
				savedPool.AccountPoolConfig.Schedule.Windows[0].EndTime = "18:02"
				if _, err := relay.poolService.SavePool(savedPool); err != nil {
					t.Fatalf("extend queued pool plan: %v", err)
				}
				extendedTimer := awaitTimer()
				if !initialTimer.stopped.Load() || extendedTimer.duration != 150*time.Second {
					t.Fatalf("extension did not replace deadline: old stopped=%t new duration=%v", initialTimer.stopped.Load(), extendedTimer.duration)
				}
				clock.Store(time.Date(2026, time.November, 2, 18, 1, 0, 0, beijingLocation).UnixNano())
				initialTimer.fire <- now()
				select {
				case <-done:
					t.Fatal("queued request expired at the superseded deadline")
				default:
				}
				queueKey := providerQueueKey("", "openai-chat", poolID)
				if position := relay.concurrencyLimiter.QueuePositions(queueKey)[queued.ActiveRequestID]; position != 1 {
					t.Fatalf("saving open plan changed queue position to %d", position)
				}
				clock.Store(time.Date(2026, time.November, 2, 18, 3, 0, 0, beijingLocation).UnixNano())
				extendedTimer.fire <- now()
			}
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("queued request did not return when its pool closed")
			}
			assertAccountScheduleHTTPClosed(t, w)
			if hits.Load() != 0 {
				t.Fatalf("closed queued request reached upstream %d times", hits.Load())
			}
			if statuses := relay.ListProviderBlacklistStatus("openai-chat", poolID); len(statuses) != 0 {
				t.Fatalf("closing queued pool blacklisted account: %+v", statuses)
			}
			relay.concurrencyLimiter.mu.Lock()
			queuedCount := len(relay.concurrencyLimiter.queues)
			reservedCount := len(relay.concurrencyLimiter.woken)
			relay.concurrencyLimiter.mu.Unlock()
			if queuedCount != 0 || reservedCount != 0 {
				t.Fatalf("closed request left queue state: queues=%d reservations=%d", queuedCount, reservedCount)
			}
		})
	}
}
