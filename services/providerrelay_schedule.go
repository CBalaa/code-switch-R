package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// Only pools resolved by the relay's routing layer have a persisted identity.
// Direct forwarding helpers may also receive a transient pool configuration.
type persistedProviderPoolContextKey struct{}

type schedulePriorUpstreamFailure struct {
	status int
	body   string
	err    error
}

// Keep an actual failed HTTP attempt separate from the later local denial.
// The caller records this failure once before returning the schedule error.
type accountPoolScheduleInterruptedError struct {
	closed  error
	failure *schedulePriorUpstreamFailure
}

func (e *accountPoolScheduleInterruptedError) Error() string { return e.closed.Error() }
func (e *accountPoolScheduleInterruptedError) Unwrap() error { return e.closed }

func withSchedulePriorUpstreamFailure(closed error, failure *schedulePriorUpstreamFailure) error {
	if failure == nil {
		return closed
	}
	return &accountPoolScheduleInterruptedError{closed: closed, failure: failure}
}

func (prs *ProviderRelayService) recordFailureBeforeScheduleClose(userID, platform string, pool *ProviderPool, provider Provider, err error) {
	var interrupted *accountPoolScheduleInterruptedError
	if !errors.As(err, &interrupted) || interrupted.failure == nil {
		return
	}
	failure := interrupted.failure
	if _, proxyFailure := isProxyRequestError(failure.err); proxyFailure || errors.Is(failure.err, context.Canceled) {
		return
	}
	body := redactProviderSecret(failure.body, provider)
	message := body
	if message == "" && failure.err != nil {
		message = redactProviderSecret(failure.err.Error(), provider)
	}
	rule := specialBlacklistRuleForFailure(pool, failure.status, body)
	prs.recordPoolAttemptError(userID, pool, provider, failure.status, rule, message)
	reason := message
	if rule == nil && failure.status > 0 {
		reason = fmt.Sprintf("HTTP %d", failure.status)
	}
	prs.recordProviderFailureWithRuleForUser(userID, platform, pool.ID, pool, provider, reason, rule)
}

func (prs *ProviderRelayService) accountPoolScheduleNow() time.Time {
	if prs.scheduleNow != nil {
		return prs.scheduleNow()
	}
	return time.Now()
}

func (prs *ProviderRelayService) accountPoolScheduleAfter(duration time.Duration) (<-chan time.Time, func()) {
	if prs.scheduleAfter != nil {
		return prs.scheduleAfter(duration)
	}
	timer := time.NewTimer(duration)
	return timer.C, func() { timer.Stop() }
}

func isAccountPoolScheduleClosed(err error) bool {
	var closed *accountPoolScheduleClosedError
	return errors.As(err, &closed)
}

// A request can wait for a proxy or queue slot while the administrator changes
// its schedule. Read the persisted pool again immediately before each send.
func (prs *ProviderRelayService) currentAccountPoolForSchedule(ctx context.Context) (*ProviderPool, error) {
	pool := providerPoolFromContext(ctx)
	persisted, _ := ctx.Value(persistedProviderPoolContextKey{}).(bool)
	if !isAccountPool(pool) || !persisted || prs.poolService == nil || pool.ID == "" {
		return pool, nil
	}
	var current *ProviderPool
	var err error
	if userID := providerPoolUserFromContext(ctx); userID != "" {
		current, err = prs.poolService.GetPoolForUser(userID, pool.ID)
	} else {
		current, err = prs.poolService.GetPool(pool.ID)
	}
	if err != nil {
		return nil, &accountPoolScheduleClosedError{PoolID: pool.ID, Cause: err}
	}
	if current == nil || !isAccountPool(current) {
		return nil, &accountPoolScheduleClosedError{PoolID: pool.ID, Cause: fmt.Errorf("号池不存在")}
	}
	return current, nil
}

func (prs *ProviderRelayService) checkCurrentAccountPoolSchedule(ctx context.Context) error {
	pool, err := prs.currentAccountPoolForSchedule(ctx)
	if err != nil {
		return err
	}
	return checkAccountPoolScheduleOpen(pool, prs.accountPoolScheduleNow())
}

func writeAccountPoolScheduleClosed(c *gin.Context, err error, requestLog *ReqeustLog) {
	if requestLog != nil {
		// A previous first-text timeout can already have its own persisted row.
		// The final local rejection still needs a separate completion record.
		if requestLog.attemptPersisted {
			requestLog.attemptPersisted = false
			requestLog.startedAt = time.Now()
			requestLog.InputTokens = 0
			requestLog.OutputTokens = 0
			requestLog.CacheCreateTokens = 0
			requestLog.CacheReadTokens = 0
			requestLog.ReasoningTokens = 0
			requestLog.UpstreamHeaderSec = 0
			requestLog.FirstEventSec = 0
			requestLog.FirstTextSec = 0
			requestLog.FirstTokenDurationSec = 0
			// The timeout row already owns these upstream totals. The local
			// rejection sends nothing upstream; finalization will still add the
			// client's request and final error response to this completion row.
			requestLog.UpstreamAttempts = 0
			requestLog.UpstreamRequestBytes = 0
			requestLog.UpstreamResponseBytes = 0
			requestLog.RetryRequestBytes = 0
			requestLog.RetryResponseBytes = 0
			requestLog.PublicIngressBytes = 0
			requestLog.PublicEgressBytes = 0
			requestLog.LocalIngressBytes = 0
			requestLog.LocalEgressBytes = 0
		}
		requestLog.Provider = ""
		requestLog.HttpCode = http.StatusServiceUnavailable
		requestLog.ErrorMessage = err.Error()
	}
	c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error(), "code": "account_pool_closed"})
}

func (prs *ProviderRelayService) removeScheduleClosedQueueItem(item *ProviderQueueItem) {
	_, queueKeys := prs.concurrencyLimiter.RemoveQueuedAndReserveNext(item.RequestID, item.UserID, item.Platform)
	queueKeys = appendStringUnique(queueKeys, providerQueueKey(item.UserID, item.Platform, item.PoolID))
	for _, key := range queueKeys {
		prs.syncProviderQueuePositions(key)
	}
}

// A schedule change and its next closing boundary both wake the waiter, without
// changing its position while the pool remains open. Already sent requests do
// not use these timers and are allowed to finish normally.
func (prs *ProviderRelayService) awaitProviderQueueTurn(c *gin.Context, item *ProviderQueueItem, requestLog *ReqeustLog) bool {
	var changes <-chan struct{}
	accountPool := isAccountPool(providerPoolFromContext(c.Request.Context()))
	if accountPool {
		var unsubscribe func()
		var err error
		changes, unsubscribe, err = subscribeAccountPoolScheduleChanges(item.UserID, item.PoolID)
		if err != nil {
			prs.removeScheduleClosedQueueItem(item)
			writeAccountPoolScheduleClosed(c, &accountPoolScheduleClosedError{PoolID: item.PoolID, Cause: err}, requestLog)
			return false
		}
		defer unsubscribe()
	}
	for {
		var closing <-chan time.Time
		stopTimer := func() {}
		if accountPool {
			pool, err := prs.currentAccountPoolForSchedule(c.Request.Context())
			now := prs.accountPoolScheduleNow()
			var evaluation accountPoolScheduleEvaluation
			if err == nil {
				evaluation, err = evaluateAccountPoolSchedule(pool, now)
				if err != nil || !evaluation.IsOpen {
					err = &accountPoolScheduleClosedError{PoolID: item.PoolID, NextOpenAt: evaluation.NextChangeAt, Cause: err}
				}
			}
			if err != nil {
				prs.removeScheduleClosedQueueItem(item)
				writeAccountPoolScheduleClosed(c, err, requestLog)
				return false
			}
			if !evaluation.NextChangeAt.IsZero() {
				closing, stopTimer = prs.accountPoolScheduleAfter(evaluation.NextChangeAt.Sub(now))
			}
		}
		select {
		case <-item.Ready:
			stopTimer()
			return true
		case <-closing:
			stopTimer()
		case <-changes:
			stopTimer()
		case <-c.Request.Context().Done():
			stopTimer()
			prs.removeScheduleClosedQueueItem(item)
			requestLog.HttpCode = 499
			requestLog.ErrorMessage = "client cancelled while queued"
			return false
		}
	}
}
