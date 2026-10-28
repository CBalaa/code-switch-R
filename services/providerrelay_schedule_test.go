package services

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestScheduleClosedAfterPersistedTimeoutKeepsBothLogResults(t *testing.T) {
	db := openRequestLogSchemaTestDB(t)
	if err := ensureRequestLogTableWithDB(db); err != nil {
		t.Fatal(err)
	}
	previousQueue := GlobalDBQueueLogs
	queue := NewDBWriteQueue(db, 32, true)
	GlobalDBQueueLogs = queue
	t.Cleanup(func() {
		_ = queue.Shutdown(time.Second)
		GlobalDBQueueLogs = previousQueue
	})
	previousTracker := defaultActiveRequestTracker
	defaultActiveRequestTracker = newActiveRequestTracker()
	t.Cleanup(func() { defaultActiveRequestTracker = previousTracker })
	entry := &ReqeustLog{
		UserID: "schedule-timeout-user", Platform: "openai-responses",
		Provider: "slow-key", Model: "gpt-5", IsStream: true,
		ClientIP: "127.0.0.1", startedAt: time.Now().Add(-5 * time.Second),
		UpstreamAttempts: 2, UpstreamRequestBytes: 100, UpstreamResponseBytes: 60,
		RetryRequestBytes: 40, RetryResponseBytes: 20,
		PublicIngressBytes: 35, PublicEgressBytes: 70,
		LocalIngressBytes: 25, LocalEgressBytes: 30,
	}
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/responses", nil)
	inbound := &trafficInboundState{writer: c.Writer}
	inbound.requestBytes.Store(50)
	c.Set(trafficInboundStateKey, inbound)
	entry.initializeTraffic(c)
	entry.ActiveRequestID = defaultActiveRequestTracker.Start(entry, entry.startedAt)
	relay := &ProviderRelayService{}
	relay.persistFirstTextTimeoutAttempt(entry)
	writeAccountPoolScheduleClosed(c, &accountPoolScheduleClosedError{PoolID: "scheduled-pool"}, entry)
	relay.finishActiveRequestLog(entry)
	assertAccountScheduleHTTPClosed(t, w)
	rows, err := db.Query(`SELECT http_code, provider, error_message FROM request_log WHERE user_id = ? ORDER BY id`, entry.UserID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var statuses []int
	for rows.Next() {
		var status int
		var provider, message string
		if err := rows.Scan(&status, &provider, &message); err != nil {
			t.Fatal(err)
		}
		statuses = append(statuses, status)
		if status == http.StatusGatewayTimeout && (provider != "slow-key" || message != firstTextTimeoutErrorBody) {
			t.Fatalf("timeout attempt identity was lost: %q %q", provider, message)
		}
		if status == http.StatusServiceUnavailable && (provider != "" || message == "") {
			t.Fatalf("local close was attributed to an upstream account: %q %q", provider, message)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 2 || statuses[0] != http.StatusGatewayTimeout || statuses[1] != http.StatusServiceUnavailable {
		t.Fatalf("persisted results = %v, want original 504 followed by local 503", statuses)
	}
	if entries := defaultActiveRequestTracker.List("", "", entry.UserID); len(entries) != 0 {
		t.Fatalf("completed close still has an active log: %+v", entries)
	}
	var attempts int
	var upstreamRequest, upstreamResponse, retryRequest, retryResponse int64
	var publicIngress, publicEgress, localIngress, localEgress, clientRequest, clientResponse int64
	err = db.QueryRow(`SELECT SUM(upstream_attempts), SUM(upstream_request_bytes), SUM(upstream_response_bytes),
		SUM(retry_request_bytes), SUM(retry_response_bytes), SUM(public_ingress_bytes), SUM(public_egress_bytes),
		SUM(local_ingress_bytes), SUM(local_egress_bytes), SUM(client_request_bytes), SUM(client_response_bytes)
		FROM request_log WHERE user_id = ?`, entry.UserID).Scan(
		&attempts, &upstreamRequest, &upstreamResponse, &retryRequest, &retryResponse,
		&publicIngress, &publicEgress, &localIngress, &localEgress, &clientRequest, &clientResponse,
	)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || upstreamRequest != 100 || upstreamResponse != 60 || retryRequest != 40 || retryResponse != 20 {
		t.Fatalf("timeout and local close double-counted upstream traffic: attempts=%d bytes=%d/%d retry=%d/%d", attempts, upstreamRequest, upstreamResponse, retryRequest, retryResponse)
	}
	responseBytes := int64(w.Body.Len())
	if publicIngress != 35 || publicEgress != 70 || localIngress != 75 || localEgress != 30+responseBytes || clientRequest != 50 || clientResponse != responseBytes {
		t.Fatalf("client or network totals lost: public=%d/%d local=%d/%d client=%d/%d response=%d", publicIngress, publicEgress, localIngress, localEgress, clientRequest, clientResponse, responseBytes)
	}
}
