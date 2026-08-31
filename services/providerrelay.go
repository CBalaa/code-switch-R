package services

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daodao97/xgo/xdb"
	"github.com/daodao97/xgo/xrequest"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// ProviderPoolProviderPenalty 池子内单个 provider 的运行时惩罚状态
type ProviderPoolProviderPenalty struct {
	UserID            string         `json:"userID,omitempty"`
	Platform          string         `json:"platform"`
	PoolID            string         `json:"poolID"`
	ProviderID        int64          `json:"providerID"`
	FailureCount      int            `json:"failureCount"`
	LastFailureAt     time.Time      `json:"lastFailureAt"`
	BlacklistedUntil  time.Time      `json:"blacklistedUntil"`
	LastReason        string         `json:"lastReason"`
	RuleFailureCounts map[string]int `json:"ruleFailureCounts,omitempty"`
}
type LastUsedProvider struct {
	UserID       string `json:"userID,omitempty"`
	Platform     string `json:"platform"`      // 平台
	PoolID       string `json:"pool_id"`       // 池子 ID（pool 维度隔离）
	ProviderName string `json:"provider_name"` // 供应商名称
	UpdatedAt    int64  `json:"updated_at"`    // 更新时间（毫秒）
}

type ProviderRelayService struct {
	providerService     *ProviderService
	poolService         *ProviderPoolService
	codexRelayKeys      *CodexRelayKeyService
	notificationService *NotificationService
	appSettings         *AppSettingsService
	proxyManager        *ProxyManager
	proxyService        *ProxyService
	trafficService      *TrafficService
	proxyClientMu       sync.Mutex
	proxyClients        map[string]*http.Client
	proxyClientLastUsed map[string]time.Time
	httpClient          *http.Client
	concurrencyLimiter  *ProviderConcurrencyLimiter
	server              *http.Server
	addr                string
	lastUsed            map[string]*LastUsedProvider // 各平台最后使用的供应商
	lastUsedMu          sync.RWMutex                 // 保护 lastUsed 的锁

	// 池子维度 provider 惩罚状态（自动拉黑）
	poolPenaltyMu         sync.Mutex
	poolPenalties         map[string]*ProviderPoolProviderPenalty
	poolAttemptLogs       *PoolAttemptLogService
	accountPoolStickyMu   sync.Mutex
	accountPoolStickiness *accountPoolStickyStore
}

func (prs *ProviderRelayService) SetPoolAttemptLogService(service *PoolAttemptLogService) {
	if prs != nil {
		prs.poolAttemptLogs = service
	}
}

func (prs *ProviderRelayService) SetTrafficService(service *TrafficService) {
	if prs != nil {
		prs.trafficService = service
	}
}

// errClientAbort 表示客户端中断连接，不应计入 provider 失败次数
var errClientAbort = errors.New("client aborted, skip failure count")
var errCodexEmptyStream = errors.New("codex upstream stream closed before useful content")
var errCodexMissingCompletion = errors.New("codex upstream stream closed before response.completed")
var errCodexTerminalStreamFailure = errors.New("codex upstream stream ended failed or incomplete before useful content")
var errCodexInitialBufferLimit = errors.New("codex upstream stream exceeded the preflight buffer before useful content")
var errCodexFirstTextTimeout = errors.New("codex upstream stream timed out before useful content")
var errProviderEmptyShell = errors.New("provider returned 200 but all token counts are zero")
var errActiveRequestRetryRequested = errors.New("active request retry requested")

// providerRequestAttempt owns the deadline for exactly one client.Do call.
// Retries must never retain this state: their direct provider/key HTTP request
// gets a fresh context, timer and start timestamp.
type providerRequestAttempt struct {
	ctx       context.Context
	startedAt time.Time
	timedOut  atomic.Bool
	stopTimer func()
	cancel    context.CancelFunc
}

func (attempt *providerRequestAttempt) stop() {
	if attempt != nil && attempt.stopTimer != nil {
		attempt.stopTimer()
	}
}

func (attempt *providerRequestAttempt) close() {
	if attempt == nil {
		return
	}
	attempt.stop()
	if attempt.cancel != nil {
		attempt.cancel()
	}
}

// firstTextTimeoutErrorBody is recorded for every configured first-text timeout.
// Keep this JSON stable because special blacklist rules can match its fields.
const firstTextTimeoutErrorBody = `{"error":{"type":"first_text_timeout","code":"first_text_timeout","message":"upstream first text timeout"}}`

const (
	emptyStreamErrorCode           = "empty_stream"
	missingCompletionErrorCode     = "missing_completion"
	terminalStreamFailureErrorCode = "terminal_stream_failure"
	initialBufferLimitErrorCode    = "initial_buffer_limit"
	streamPreflightErrorCode       = "stream_preflight_error"
	invalidStreamContentTypeCode   = "invalid_stream_content_type"
	maxResponsesPreflightAttempts  = 2
	responsesPreflightRetryDelay   = 100 * time.Millisecond
)

// upstreamProtocolError represents a syntactically successful HTTP response
// that is unusable at the relay protocol layer. The relay status/body are what
// clients and blacklist rules should observe; upstreamStatus preserves the
// original transport result for diagnostics.
type upstreamProtocolError struct {
	statusCode     int
	upstreamStatus int
	code           string
	message        string
	body           []byte
	cause          error
}

func newUpstreamProtocolError(upstreamStatus int, code, message string, cause error) *upstreamProtocolError {
	body := []byte(fmt.Sprintf(
		`{"error":{"type":"upstream_protocol_error","code":%q,"message":%q,"upstream_status":%d}}`,
		code,
		message,
		upstreamStatus,
	))
	return &upstreamProtocolError{
		statusCode:     http.StatusBadGateway,
		upstreamStatus: upstreamStatus,
		code:           code,
		message:        message,
		body:           body,
		cause:          cause,
	}
}

func newEmptyStreamProtocolError(upstreamStatus int) *upstreamProtocolError {
	return newUpstreamProtocolError(
		upstreamStatus,
		emptyStreamErrorCode,
		errCodexEmptyStream.Error(),
		errCodexEmptyStream,
	)
}

func newCodexStreamPreflightProtocolError(upstreamStatus int, cause error) *upstreamProtocolError {
	switch {
	case errors.Is(cause, errCodexEmptyStream):
		return newEmptyStreamProtocolError(upstreamStatus)
	case errors.Is(cause, errCodexMissingCompletion):
		return newUpstreamProtocolError(
			upstreamStatus,
			missingCompletionErrorCode,
			errCodexMissingCompletion.Error(),
			errCodexMissingCompletion,
		)
	case errors.Is(cause, errCodexTerminalStreamFailure):
		return newUpstreamProtocolError(
			upstreamStatus,
			terminalStreamFailureErrorCode,
			errCodexTerminalStreamFailure.Error(),
			errCodexTerminalStreamFailure,
		)
	case errors.Is(cause, errCodexInitialBufferLimit):
		return newUpstreamProtocolError(
			upstreamStatus,
			initialBufferLimitErrorCode,
			errCodexInitialBufferLimit.Error(),
			errCodexInitialBufferLimit,
		)
	default:
		return newUpstreamProtocolError(
			upstreamStatus,
			streamPreflightErrorCode,
			"codex upstream stream failed before useful content",
			cause,
		)
	}
}

// committedCodexStreamProtocolError preserves the provider failure after an
// SSE response has started. The response cannot be replayed at that point,
// because doing so would append a second model output to the same client stream.
func committedCodexStreamProtocolError(upstreamStatus int, responseWritten bool, copyErr error, requestLog *ReqeustLog) *upstreamProtocolError {
	if !responseWritten || copyErr == nil {
		return nil
	}
	if !errors.Is(copyErr, errCodexMissingCompletion) && !errors.Is(copyErr, errCodexTerminalStreamFailure) {
		return nil
	}
	protocolErr := newCodexStreamPreflightProtocolError(upstreamStatus, copyErr)
	setRequestLogProtocolError(requestLog, protocolErr)
	return protocolErr
}

func newInvalidStreamContentTypeProtocolError(upstreamStatus int, cause error) *upstreamProtocolError {
	return newUpstreamProtocolError(
		upstreamStatus,
		invalidStreamContentTypeCode,
		"codex upstream returned HTML instead of an SSE stream",
		cause,
	)
}

func (e *upstreamProtocolError) Error() string {
	if e == nil {
		return "upstream protocol error"
	}
	return fmt.Sprintf("upstream protocol error %s: %s (upstream HTTP %d)", e.code, e.message, e.upstreamStatus)
}

func (e *upstreamProtocolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

func writeUpstreamProtocolError(c *gin.Context, protocolErr *upstreamProtocolError) {
	if c == nil || protocolErr == nil {
		return
	}
	c.Data(protocolErr.statusCode, "application/json; charset=utf-8", protocolErr.body)
}

func setRequestLogProtocolError(requestLog *ReqeustLog, protocolErr *upstreamProtocolError) {
	if requestLog == nil || protocolErr == nil {
		return
	}
	requestLog.HttpCode = protocolErr.statusCode
	requestLog.ErrorMessage = string(protocolErr.body)
}

func protocolErrorFromError(err error) (*upstreamProtocolError, bool) {
	var protocolErr *upstreamProtocolError
	if !errors.As(err, &protocolErr) || protocolErr == nil {
		return nil, false
	}
	return protocolErr, true
}

func emptyStreamProtocolError(err error) (*upstreamProtocolError, bool) {
	protocolErr, ok := protocolErrorFromError(err)
	if !ok || protocolErr.code != emptyStreamErrorCode {
		return nil, false
	}
	return protocolErr, true
}

func shouldRetryResponsesPreflightFailure(kind string, isStream bool, accountPool bool, responseWriter http.ResponseWriter, err error) bool {
	if accountPool || kind != "openai-responses" || !isStream || responseWriterWritten(responseWriter) {
		return false
	}
	protocolErr, ok := protocolErrorFromError(err)
	if !ok {
		return false
	}
	switch protocolErr.code {
	case terminalStreamFailureErrorCode, streamPreflightErrorCode:
		return true
	default:
		return false
	}
}

func waitBeforeResponsesPreflightRetry(ctx context.Context) error {
	timer := time.NewTimer(responsesPreflightRetryDelay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// upstreamClientRequestError preserves a request-scoped upstream 4xx response
// so an account pool can return it without trying every account key.
type upstreamClientRequestError struct {
	statusCode int
	header     http.Header
	body       []byte
}

func (e *upstreamClientRequestError) Error() string {
	if e == nil {
		return "upstream client request error"
	}
	message := summarizeBodyForError(string(e.body), 1000)
	if message == "" {
		return fmt.Sprintf("upstream status %d", e.statusCode)
	}
	return fmt.Sprintf("upstream status %d: %s", e.statusCode, message)
}

// isRequestScopedUpstream4xx reports statuses which describe this request,
// rather than the account key. Authentication, account, rate-limit, and
// timeout statuses remain eligible for account-pool failover.
func isRequestScopedUpstream4xx(status int) bool {
	if status < http.StatusBadRequest || status >= http.StatusInternalServerError {
		return false
	}
	switch status {
	case http.StatusUnauthorized,
		http.StatusPaymentRequired,
		http.StatusForbidden,
		http.StatusProxyAuthRequired,
		http.StatusRequestTimeout,
		http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func clientErrorResponseHeaders(header http.Header) http.Header {
	// Error bodies can be useful to the relay caller, but upstream headers may
	// contain credentials, cookies, or provider-only diagnostics.
	sanitized := make(http.Header)
	if contentType := strings.TrimSpace(header.Get("Content-Type")); contentType != "" {
		sanitized.Set("Content-Type", contentType)
	}
	return sanitized
}

func newUpstreamClientRequestError(resp *xrequest.Response, provider Provider) (*upstreamClientRequestError, error) {
	if resp == nil || resp.RawResponse == nil {
		return nil, errors.New("empty upstream response")
	}
	body, err := readResponseBody(resp)
	if err != nil {
		return nil, err
	}
	return &upstreamClientRequestError{
		statusCode: resp.StatusCode(),
		header:     clientErrorResponseHeaders(resp.RawResponse.Header),
		body:       []byte(redactProviderSecret(string(body), provider)),
	}, nil
}

func writeUpstreamClientRequestError(c *gin.Context, upstreamErr *upstreamClientRequestError) {
	if c == nil || upstreamErr == nil {
		return
	}
	copyResponseHeaders(c.Writer, upstreamErr.header)
	c.Data(upstreamErr.statusCode, upstreamErr.header.Get("Content-Type"), upstreamErr.body)
}

func isProxyRequestError(err error) (*proxyRequestError, bool) {
	var proxyErr *proxyRequestError
	if errors.As(err, &proxyErr) {
		return proxyErr, true
	}
	return nil, false
}

const relayTrustedProxiesEnv = "CODE_SWITCH_TRUSTED_PROXIES"

func NewProviderRelayService(providerService *ProviderService, poolService *ProviderPoolService, codexRelayKeys *CodexRelayKeyService, notificationService *NotificationService, appSettings *AppSettingsService, addr string) *ProviderRelayService {
	if addr == "" {
		addr = DefaultRelayBindAddr
	}
	if codexRelayKeys == nil {
		codexRelayKeys = NewCodexRelayKeyService()
	}
	if poolService == nil {
		poolService = NewProviderPoolService()
	}

	// 【修复】数据库初始化已移至 main.go 的 InitDatabase()
	// 此处不再调用 xdb.Inits()、ensureRequestLogTable()

	return &ProviderRelayService{
		providerService:     providerService,
		poolService:         poolService,
		codexRelayKeys:      codexRelayKeys,
		notificationService: notificationService,
		appSettings:         appSettings,
		httpClient:          newRelayHTTPClient(),
		proxyClients:        make(map[string]*http.Client),
		proxyClientLastUsed: make(map[string]time.Time),
		concurrencyLimiter:  NewProviderConcurrencyLimiter(),
		addr:                addr,
		lastUsed: map[string]*LastUsedProvider{
			"claude":           nil,
			"openai-responses": nil,
			"openai-chat":      nil,
		},
		poolPenalties:         make(map[string]*ProviderPoolProviderPenalty),
		accountPoolStickiness: newAccountPoolStickyStore(),
	}
}

func (prs *ProviderRelayService) accountPoolStickyStore() *accountPoolStickyStore {
	if prs == nil {
		return nil
	}
	prs.accountPoolStickyMu.Lock()
	defer prs.accountPoolStickyMu.Unlock()
	if prs.accountPoolStickiness == nil {
		prs.accountPoolStickiness = newAccountPoolStickyStore()
	}
	return prs.accountPoolStickiness
}

func (prs *ProviderRelayService) SetProxyManager(manager *ProxyManager) {
	if prs == nil {
		return
	}
	prs.proxyManager = manager
}

// SetProxyService enables user-scoped account-pool proxy resolution. The
// manager remains separately available for request lease tracking.
func (prs *ProviderRelayService) SetProxyService(service *ProxyService) {
	if prs == nil {
		return
	}
	prs.proxyService = service
}

type poolProxyContextKey struct{}
type poolProxyUserContextKey struct{}
type accountPoolStickyRequestContextKey struct{}

func withProviderPoolContext(ctx context.Context, pool *ProviderPool, userID string) context.Context {
	if pool == nil {
		return ctx
	}
	ctx = context.WithValue(ctx, poolProxyContextKey{}, pool)
	return context.WithValue(ctx, poolProxyUserContextKey{}, userID)
}

func providerPoolUserFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	userID, _ := ctx.Value(poolProxyUserContextKey{}).(string)
	return strings.TrimSpace(userID)
}

func providerPoolFromContext(ctx context.Context) *ProviderPool {
	if ctx == nil {
		return nil
	}
	pool, _ := ctx.Value(poolProxyContextKey{}).(*ProviderPool)
	return pool
}

func withAccountPoolStickyRequestContext(ctx context.Context, request *accountPoolStickyRequest) context.Context {
	if request == nil {
		return ctx
	}
	return context.WithValue(ctx, accountPoolStickyRequestContextKey{}, request)
}

func accountPoolStickyRequestFromContext(ctx context.Context) *accountPoolStickyRequest {
	if ctx == nil {
		return nil
	}
	request, _ := ctx.Value(accountPoolStickyRequestContextKey{}).(*accountPoolStickyRequest)
	return request
}

func (prs *ProviderRelayService) requestClient(ctx context.Context) (*http.Client, proxyEndpoint, error) {
	base := prs.httpClient
	if base == nil {
		base = http.DefaultClient
	}
	pool := providerPoolFromContext(ctx)
	if pool == nil || pool.ProxyConfig == nil || !pool.ProxyConfig.Enabled {
		return base, proxyEndpoint{}, nil
	}
	if pool.ProxyConfig.Selection == AccountPoolProxySelectionNone {
		return nil, proxyEndpoint{}, errors.New("号池已启用代理，但未选择代理策略")
	}
	if prs.proxyManager == nil && prs.proxyService == nil {
		return nil, proxyEndpoint{}, errors.New("号池已启用代理，但代理服务未初始化")
	}
	userID := providerPoolUserFromContext(ctx)
	poolKey := userID + "\x00" + pool.ID
	var endpoint proxyEndpoint
	var err error
	if prs.proxyService != nil {
		baseURL := ""
		if pool.AccountPoolConfig != nil {
			baseURL = pool.AccountPoolConfig.APIURL
		}
		endpoint, err = prs.proxyService.ProxyURLForPoolWithBaseURL(ctx, userID, pool.ID, pool.ProxyConfig, baseURL)
	} else {
		endpoint, err = prs.proxyManager.ProxyURLForPool(ctx, poolKey, pool.ProxyConfig)
	}
	if err != nil {
		if isAutoProxyUnavailableError(err) {
			prs.disableAutoPoolProxy(userID, pool)
		}
		return nil, proxyEndpoint{}, &proxyRequestError{PoolKey: poolKey, Err: err}
	}
	parsed, err := url.Parse(endpoint.URL)
	if err != nil {
		return nil, proxyEndpoint{}, err
	}
	clientKey := fmt.Sprintf("%s\x00%s\x00%s\x00%d", poolKey, endpoint.Node, endpoint.URL, endpoint.Generation)
	prs.proxyClientMu.Lock()
	if prs.proxyClients == nil {
		prs.proxyClients = make(map[string]*http.Client)
	}
	if prs.proxyClientLastUsed == nil {
		prs.proxyClientLastUsed = make(map[string]time.Time)
	}
	now := time.Now()
	for key, lastUsed := range prs.proxyClientLastUsed {
		if now.Sub(lastUsed) > 10*time.Minute {
			if oldClient := prs.proxyClients[key]; oldClient != nil {
				oldClient.CloseIdleConnections()
			}
			delete(prs.proxyClients, key)
			delete(prs.proxyClientLastUsed, key)
		}
	}
	if client, ok := prs.proxyClients[clientKey]; ok {
		prs.proxyClientLastUsed[clientKey] = now
		prs.proxyClientMu.Unlock()
		return client, endpoint, nil
	}
	transport, ok := base.Transport.(*http.Transport)
	if !ok || transport == nil {
		transport = newRelayHTTPClient().Transport.(*http.Transport)
	}
	clone := transport.Clone()
	clone.Proxy = http.ProxyURL(parsed)
	cloneTransport := wrapProxyTransport(clone, prs.proxyManager, endpoint.Key, endpoint.Node, endpoint.Generation)
	client := &http.Client{Transport: cloneTransport, Timeout: base.Timeout, CheckRedirect: base.CheckRedirect, Jar: base.Jar}
	prs.proxyClients[clientKey] = client
	prs.proxyClientLastUsed[clientKey] = now
	prs.proxyClientMu.Unlock()
	return client, endpoint, nil
}

func isAutoProxyUnavailableError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "自动选择没有可用代理节点")
}

// disableAutoPoolProxy persists the direct-routing fallback after automatic
// selection proves that every candidate is unavailable. The in-memory pool is
// updated too, so retries in the current request immediately stop using it.
func (prs *ProviderRelayService) disableAutoPoolProxy(userID string, pool *ProviderPool) {
	if prs == nil || pool == nil || pool.ProxyConfig == nil || !pool.ProxyConfig.Enabled || pool.ProxyConfig.Selection != AccountPoolProxySelectionAuto || !pool.ProxyConfig.AutoDisableWhenNoAvailable {
		return
	}

	pool.ProxyConfig.Enabled = false
	pool.ProxyConfig.Selection = AccountPoolProxySelectionNone
	pool.ProxyConfig.ProxyNodeID = ""

	userID = strings.TrimSpace(userID)
	if prs.poolService == nil || userID == "" || strings.TrimSpace(pool.ID) == "" {
		return
	}

	persisted, err := prs.poolService.GetPoolForUser(userID, pool.ID)
	if err != nil || persisted == nil || persisted.ProxyConfig == nil || !persisted.ProxyConfig.Enabled || persisted.ProxyConfig.Selection != AccountPoolProxySelectionAuto || !persisted.ProxyConfig.AutoDisableWhenNoAvailable {
		return
	}
	persisted.ProxyConfig.Enabled = false
	persisted.ProxyConfig.Selection = AccountPoolProxySelectionNone
	persisted.ProxyConfig.ProxyNodeID = ""
	if _, err := prs.poolService.SavePoolForUser(userID, persisted); err != nil {
		fmt.Printf("[proxy] 自动选择无可用节点，关闭号池代理配置失败: pool=%s err=%v\n", pool.ID, err)
		return
	}

	if prs.proxyService != nil {
		baseURL := ""
		if persisted.AccountPoolConfig != nil {
			baseURL = persisted.AccountPoolConfig.APIURL
		}
		if err := prs.proxyService.SyncPoolProxyWithBaseURL(userID, persisted.ID, persisted.ProxyConfig, baseURL); err != nil {
			fmt.Printf("[proxy] 自动选择无可用节点，清理号池代理 listener 失败: pool=%s err=%v\n", pool.ID, err)
		}
	}
	fmt.Printf("[proxy] 自动选择无可用代理节点，已关闭号池使用代理: pool=%s\n", pool.ID)
}

func (prs *ProviderRelayService) recordResponsesCloudflareBlock(ctx context.Context, endpoint proxyEndpoint, responsesURL string, response *http.Response) {
	if prs == nil || prs.proxyService == nil || strings.TrimSpace(endpoint.SelectedNode) == "" || !cloudflareBlockedResponse(response) {
		return
	}
	pool := providerPoolFromContext(ctx)
	if pool == nil || pool.ProxyConfig == nil || !pool.ProxyConfig.Enabled || pool.AccountPoolConfig == nil {
		return
	}
	prs.proxyService.RecordResponsesCloudflareBlock(endpoint.SelectedNode, responsesURL, pool.AccountPoolConfig.APIURL)
}

func newRelayHTTPClient() *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   50,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	return &http.Client{Transport: transport}
}

func clientIPFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}

	directIP, fallback := directClientIPFromRequest(r)
	if !directIP.IsValid() {
		return fallback
	}

	if relayIsTrustedProxy(directIP) {
		for _, part := range strings.Split(r.Header.Get("X-Forwarded-For"), ",") {
			candidate := strings.TrimSpace(part)
			if candidate == "" {
				continue
			}
			if ip, err := netip.ParseAddr(candidate); err == nil {
				return ip.String()
			}
		}

		if candidate := strings.TrimSpace(r.Header.Get("X-Real-IP")); candidate != "" {
			if ip, err := netip.ParseAddr(candidate); err == nil {
				return ip.String()
			}
		}
	}

	return directIP.String()
}

func directClientIPFromRequest(r *http.Request) (netip.Addr, string) {
	if r == nil {
		return netip.Addr{}, ""
	}

	remoteAddr := strings.TrimSpace(r.RemoteAddr)
	if remoteAddr == "" {
		return netip.Addr{}, ""
	}

	host := remoteAddr
	if parsedHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = parsedHost
	}

	host = strings.Trim(host, "[]")
	ip, err := netip.ParseAddr(host)
	if err == nil {
		return ip, ""
	}

	return netip.Addr{}, host
}

func relayIsTrustedProxy(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	prefixes := relayTrustedProxyPrefixes()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func relayTrustedProxyPrefixes() []netip.Prefix {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("127.0.0.0/8"),
		netip.MustParsePrefix("::1/128"),
	}

	value := strings.TrimSpace(os.Getenv(relayTrustedProxiesEnv))
	if value == "" {
		return prefixes
	}

	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			prefix, err := netip.ParsePrefix(part)
			if err == nil {
				prefixes = append(prefixes, prefix)
			}
			continue
		}
		addr, err := netip.ParseAddr(part)
		if err == nil {
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}
	}

	return prefixes
}

func lastUsedKey(userID, platform, poolID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return platform + ":" + poolID
	}
	return userID + ":" + platform + ":" + poolID
}

// setLastUsedProviderForUser 记录最后使用的供应商（user + platform + poolID 维度）
// 不同用户和不同 pool/key 之间不互相影响
func (prs *ProviderRelayService) setLastUsedProviderForUser(userID, platform, poolID, providerName string) {
	key := lastUsedKey(userID, platform, poolID)
	prs.lastUsedMu.Lock()
	defer prs.lastUsedMu.Unlock()
	prs.lastUsed[key] = &LastUsedProvider{
		UserID:       strings.TrimSpace(userID),
		Platform:     platform,
		PoolID:       poolID,
		ProviderName: providerName,
		UpdatedAt:    time.Now().UnixMilli(),
	}
}

// setLastUsedProvider 记录最后使用的供应商（旧兼容 API）。
func (prs *ProviderRelayService) setLastUsedProvider(platform, poolID, providerName string) {
	prs.setLastUsedProviderForUser("", platform, poolID, providerName)
}

// GetLastUsedProvider 获取指定平台最后使用的供应商（兼容旧 API，返回任意 pool 的）
func (prs *ProviderRelayService) GetLastUsedProvider(platform string) *LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	// 返回该 platform 下任意 pool 的 last used
	for k, v := range prs.lastUsed {
		if strings.HasPrefix(k, platform+":") && v != nil {
			return v
		}
	}
	return prs.lastUsed[platform] // 兼容旧的纯 platform key
}

// GetAllLastUsedProvidersForUser 获取当前用户的最后使用供应商状态。
func (prs *ProviderRelayService) GetAllLastUsedProvidersForUser(userID string) []*LastUsedProvider {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return prs.GetAllLastUsedProviders()
	}
	prefix := userID + ":"
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	result := make([]*LastUsedProvider, 0, len(prs.lastUsed))
	for key, v := range prs.lastUsed {
		if v != nil && strings.HasPrefix(key, prefix) {
			result = append(result, v)
		}
	}
	return result
}

// GetLastUsedProviderByPool 获取指定平台+池子最后使用的供应商
func (prs *ProviderRelayService) GetLastUsedProviderByPool(platform, poolID string) *LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	key := platform + ":" + poolID
	return prs.lastUsed[key]
}

// GetAllLastUsedProviders 获取所有最后使用的供应商（返回 pool 维度）
func (prs *ProviderRelayService) GetAllLastUsedProviders() []*LastUsedProvider {
	prs.lastUsedMu.RLock()
	defer prs.lastUsedMu.RUnlock()
	result := make([]*LastUsedProvider, 0, len(prs.lastUsed))
	for _, v := range prs.lastUsed {
		if v != nil {
			result = append(result, v)
		}
	}
	return result
}

func firstTextRetryTimeout(pool *ProviderPool) time.Duration {
	if pool == nil || !pool.FirstTextRetryEnabled {
		return 0
	}
	if pool.FirstTextRetryTimeoutSeconds < minFirstTextRetryTimeoutSeconds || pool.FirstTextRetryTimeoutSeconds > maxFirstTextRetryTimeoutSeconds {
		return time.Duration(defaultFirstTextRetryTimeoutSeconds) * time.Second
	}
	return time.Duration(pool.FirstTextRetryTimeoutSeconds) * time.Second
}

func (prs *ProviderRelayService) shouldUseCodexStreamGuard(kind, endpoint string) bool {
	// Delayed commitment is now a Responses protocol invariant. The legacy
	// setting remains readable for configuration compatibility, but disabling it
	// must not restore HTTP 200 + empty stream behavior.
	if kind == "openai-responses" {
		return true
	}
	return strings.EqualFold(kind, "codex") && isResponsesEndpoint(endpoint)
}

// Responses streams always use a preflight guard. This is a protocol invariant:
// HTTP 200 is not committed until the upstream has produced useful output.
func (prs *ProviderRelayService) shouldUseResponseStreamGuard(c *gin.Context, kind, endpoint string) bool {
	if c != nil && c.Request != nil && accountPoolStickyRequestFromContext(c.Request.Context()) != nil {
		return true
	}
	return prs.shouldUseCodexStreamGuard(kind, endpoint)
}

func (prs *ProviderRelayService) shouldRequireProviderEnabled(kind string) bool {
	if kind == "openai-responses" {
		codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
		status, err := codexSettings.ProxyStatus()
		if err != nil {
			fmt.Printf("[WARN] 读取 OpenAI Responses 托管状态失败，保守使用 provider 开关: %v\n", err)
			return true
		}
		return status.Enabled
	}
	if kind == "openai-chat" {
		codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
		status, err := codexSettings.ProxyStatus()
		if err != nil {
			fmt.Printf("[WARN] 读取 OpenAI Chat 托管状态失败，保守使用 provider 开关: %v\n", err)
			return true
		}
		return status.Enabled
	}
	if !strings.EqualFold(kind, "codex") {
		return true
	}
	codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
	status, err := codexSettings.ProxyStatus()
	if err != nil {
		fmt.Printf("[WARN] 读取 Codex 托管状态失败，保守使用 provider 开关: %v\n", err)
		return true
	}
	return status.Enabled
}

func (prs *ProviderRelayService) codexDirectAppliedProviderFilter(kind string, requireProviderEnabled bool) (*int64, bool) {
	if kind == "openai-chat" {
		return nil, false
	}
	if kind != "openai-responses" && !strings.EqualFold(kind, "codex") {
		return nil, false
	}
	if requireProviderEnabled {
		return nil, false
	}
	codexSettings := NewCodexSettingsService(prs.Addr(), prs.codexRelayKeys)
	id, err := codexSettings.GetDirectAppliedProviderID()
	if err != nil {
		fmt.Printf("[WARN] 读取 Codex 直接应用供应商失败，非托管模式下不启用 Codex provider: %v\n", err)
		return nil, true
	}
	return id, true
}

// penaltyKey builds a stable key for user/pool-level provider penalty state.
func penaltyKey(userID, platform, poolID string, providerID int64) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Sprintf("%s:%s:%d", platform, poolID, providerID)
	}
	return fmt.Sprintf("%s:%s:%s:%d", userID, platform, poolID, providerID)
}

func penaltyKeyPrefix(userID, platform, poolID string) string {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return platform + ":" + poolID + ":"
	}
	return userID + ":" + platform + ":" + poolID + ":"
}

// getProviderLevelInPool resolves the Level for a provider within a pool.
// Only uses pool member Level; defaults to 1 if not set.
func getProviderLevelInPool(pool *ProviderPool, provider Provider) int {
	if pool != nil {
		for _, m := range pool.Members {
			if m.ProviderID == provider.ID {
				if m.Level > 0 {
					return m.Level
				}
				break
			}
		}
	}
	return 1
}

func nextProviderNameAfterIndex(levels []int, levelGroups map[int][]Provider, currentLevel int, currentIndex int) string {
	if providersInLevel, ok := levelGroups[currentLevel]; ok && currentIndex+1 < len(providersInLevel) {
		return providersInLevel[currentIndex+1].Name
	}
	for _, nextLevel := range levels {
		if nextLevel <= currentLevel {
			continue
		}
		if providers := levelGroups[nextLevel]; len(providers) > 0 {
			return providers[0].Name
		}
	}
	return ""
}

type providerAttemptPlan struct {
	pool           *ProviderPool
	userID         string
	poolID         string
	active         []Provider
	levelGroups    map[int][]Provider
	levels         []int
	allBlacklisted bool
}

func isAccountPool(pool *ProviderPool) bool {
	return pool != nil && normalizedProviderPoolType(pool.PoolType) == ProviderPoolTypeAccount
}

func resetProviderAttemptPlanOrder(plan *providerAttemptPlan, providers []Provider) {
	if plan == nil {
		return
	}
	plan.active = append([]Provider(nil), providers...)
	plan.levelGroups = make(map[int][]Provider)
	for _, provider := range plan.active {
		level := getProviderLevelInPool(plan.pool, provider)
		plan.levelGroups[level] = append(plan.levelGroups[level], provider)
	}
	plan.levels = plan.levels[:0]
	for level := range plan.levelGroups {
		plan.levels = append(plan.levels, level)
	}
	sort.Ints(plan.levels)
}

func (prs *ProviderRelayService) beginAccountPoolStickyRequest(c *gin.Context, plan *providerAttemptPlan, body []byte) *accountPoolStickyRequest {
	if prs == nil || c == nil || plan == nil || !isAccountPool(plan.pool) {
		return nil
	}
	store := prs.accountPoolStickyStore()
	if store == nil {
		return nil
	}
	scope := newAccountPoolStickyScope(plan.userID, relayKeyIDFromContext(c), plan.pool.Platform, plan.poolID)
	return store.begin(scope, accountPoolRequestIdentityFromBody(body), plan.active)
}

func (prs *ProviderRelayService) reorderAccountPoolAttemptPlan(plan *providerAttemptPlan, request *accountPoolStickyRequest) {
	if prs == nil || plan == nil || request == nil || !isAccountPool(plan.pool) {
		return
	}
	ordered := prs.accountPoolStickyStore().order(request, plan.active)
	resetProviderAttemptPlanOrder(plan, ordered)
}

func (prs *ProviderRelayService) commitAccountPoolStickyResponse(c *gin.Context, provider Provider, responseID string) {
	if prs == nil || c == nil {
		return
	}
	request := accountPoolStickyRequestFromContext(c.Request.Context())
	if request == nil {
		return
	}
	if prs.isProviderBlacklistedForUser(request.scope.userID, request.scope.platform, request.scope.poolID, provider.ID) {
		// A concurrent request can finish after another request blacklists this
		// account key. Do not resurrect a sticky binding for an unavailable key.
		return
	}
	prs.accountPoolStickyStore().commit(request, provider.ID, responseID)
}

func (prs *ProviderRelayService) responseStreamGuardOptions(c *gin.Context, provider Provider, firstUsefulContentTimeout time.Duration) codexStreamGuardOptions {
	options := codexStreamGuardOptions{
		firstUsefulContentTimeout:    firstUsefulContentTimeout,
		deferInitialKeepAlive:        true,
		disableKeepAliveUntilRelease: true,
	}
	if prs == nil || c == nil || accountPoolStickyRequestFromContext(c.Request.Context()) == nil {
		return options
	}
	return codexStreamGuardOptions{
		firstUsefulContentTimeout: options.firstUsefulContentTimeout,
		// Every guarded Responses stream stays uncommitted until useful content
		// arrives. Account pools additionally commit the successful response ID
		// for sticky continuation routing.
		deferInitialKeepAlive:        options.deferInitialKeepAlive,
		disableKeepAliveUntilRelease: options.disableKeepAliveUntilRelease,
		onSuccessfulCompleted: func(responseID string) {
			prs.commitAccountPoolStickyResponse(c, provider, responseID)
		},
	}
}

// isProviderBlacklistedForUser checks whether a provider is currently blacklisted in the given user pool.
func (prs *ProviderRelayService) isProviderBlacklistedForUser(userID, platform, poolID string, providerID int64) bool {
	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()

	key := penaltyKey(userID, platform, poolID, providerID)
	p, ok := prs.poolPenalties[key]
	if !ok {
		return false
	}
	if p.BlacklistedUntil.IsZero() {
		return false
	}
	if time.Now().After(p.BlacklistedUntil) {
		// 懒清理：过期自动恢复
		delete(prs.poolPenalties, key)
		return false
	}
	return true
}

// isProviderBlacklisted checks whether a provider is currently blacklisted in the given pool.
func (prs *ProviderRelayService) isProviderBlacklisted(platform, poolID string, providerID int64) bool {
	return prs.isProviderBlacklistedForUser("", platform, poolID, providerID)
}

// filterBlacklistedProvidersForUser removes blacklisted providers from a candidate list.
func (prs *ProviderRelayService) filterBlacklistedProvidersForUser(userID, platform, poolID string, providers []Provider) []Provider {
	if len(providers) == 0 {
		return providers
	}
	filtered := make([]Provider, 0, len(providers))
	for _, p := range providers {
		if prs.isProviderBlacklistedForUser(userID, platform, poolID, p.ID) {
			continue
		}
		filtered = append(filtered, p)
	}
	return filtered
}

// filterBlacklistedProviders removes blacklisted providers from a candidate list.
func (prs *ProviderRelayService) filterBlacklistedProviders(platform, poolID string, providers []Provider) []Provider {
	return prs.filterBlacklistedProvidersForUser("", platform, poolID, providers)
}

// recordProviderSuccessForUser clears the failure count for a provider in a pool.
func (prs *ProviderRelayService) recordProviderSuccessForUser(userID, platform, poolID string, provider Provider) {
	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()
	delete(prs.poolPenalties, penaltyKey(userID, platform, poolID, provider.ID))
}

func specialBlacklistRuleForFailure(pool *ProviderPool, status int, errorBody string) *SpecialBlacklistRule {
	if pool == nil || status < 100 || status > 599 {
		return nil
	}
	for index := range pool.SpecialBlacklistRules {
		rule := &pool.SpecialBlacklistRules[index]
		if rule.HTTPStatus != status {
			continue
		}
		if rule.JSONPath == "" {
			return rule
		}
		var body interface{}
		if json.Unmarshal([]byte(errorBody), &body) != nil {
			continue
		}
		actual, found := jsonValueAtPath(body, rule.JSONPath)
		if !found {
			continue
		}
		var expected interface{}
		if json.Unmarshal([]byte(rule.ExpectedJSONValue), &expected) != nil {
			continue // SavePool validates this; keep runtime fail-closed for stale data.
		}
		if reflect.DeepEqual(actual, expected) {
			return rule
		}
	}
	return nil
}

func jsonValueAtPath(value interface{}, path string) (interface{}, bool) {
	current := value
	for _, segment := range strings.Split(path, ".") {
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		current, ok = object[segment]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

func (prs *ProviderRelayService) recordPoolAttemptError(userID string, pool *ProviderPool, provider Provider, status int, rule *SpecialBlacklistRule, errorMessage string) {
	if prs == nil || prs.poolAttemptLogs == nil || strings.TrimSpace(userID) == "" || pool == nil {
		return
	}
	subject := strings.TrimSpace(provider.Name)
	if isValidAccountPoolKeyID(provider.ID) {
		subject = maskedPoolAttemptKey(provider.APIKey)
	}
	if subject == "" {
		subject = "(unknown)"
	}
	parts := []string{fmt.Sprintf("Pool attempt failed | pool=%s provider=%s", pool.Name, subject)}
	if status > 0 {
		parts = append(parts, fmt.Sprintf("HTTP %d", status))
	}
	if rule != nil {
		parts = append(parts, fmt.Sprintf("rule=%s", rule.Name))
	}
	if message := summarizeBodyForError(redactProviderSecret(errorMessage, provider), 500); message != "" {
		parts = append(parts, message)
	}
	level := "WARN"
	if status >= 500 || status == 0 {
		level = "ERROR"
	}
	prs.poolAttemptLogs.Add(userID, ConsoleLog{Timestamp: time.Now(), Level: level, Message: strings.Join(parts, " | ")})
}

func maskedPoolAttemptKey(key string) string {
	key = strings.TrimSpace(key)
	if len(key) <= 4 {
		return "****"
	}
	return "****" + key[len(key)-4:]
}

// recordProviderSuccess clears the failure count for a provider in a pool.
func (prs *ProviderRelayService) recordProviderSuccess(platform, poolID string, provider Provider) {
	prs.recordProviderSuccessForUser("", platform, poolID, provider)
}

// recordProviderFailureForUser increments the consecutive failure count and, if the threshold
// is reached, blacklists the provider. Returns true when this failure resulted in a new
// blacklist.
func (prs *ProviderRelayService) recordProviderFailureForUser(userID, platform, poolID string, pool *ProviderPool, provider Provider, reason string) bool {
	return prs.recordProviderFailureWithRuleForUser(userID, platform, poolID, pool, provider, reason, nil)
}

func (prs *ProviderRelayService) recordProviderFailureWithRuleForUser(userID, platform, poolID string, pool *ProviderPool, provider Provider, reason string, rule *SpecialBlacklistRule) bool {
	if pool == nil {
		return false
	}
	// 自动拉黑仅在托管模式下生效（手动模式只有一个直接应用的 provider，无需拉黑）
	if pool.Mode != ProviderPoolModeManaged {
		return false
	}
	isAccountPool := normalizedProviderPoolType(pool.PoolType) == ProviderPoolTypeAccount
	if !isAccountPool && !pool.AutoBlacklistEnabled {
		return false
	}
	threshold := pool.AutoBlacklistThreshold
	durationMinutes := pool.AutoBlacklistDurationMinutes
	if rule != nil {
		threshold = rule.Threshold
		durationMinutes = rule.DurationMinutes
	} else {
		if threshold <= 0 {
			threshold = 3
		} else if isAccountPool && threshold > maxAccountPoolBlacklistThreshold {
			threshold = maxAccountPoolBlacklistThreshold
		}
		if durationMinutes <= 0 {
			durationMinutes = 10
		} else if isAccountPool && durationMinutes > maxAccountPoolBlacklistDurationMinutes {
			durationMinutes = maxAccountPoolBlacklistDurationMinutes
		}
	}

	key := penaltyKey(userID, platform, poolID, provider.ID)
	prs.poolPenaltyMu.Lock()

	p, ok := prs.poolPenalties[key]
	if !ok {
		p = &ProviderPoolProviderPenalty{
			UserID:     strings.TrimSpace(userID),
			Platform:   platform,
			PoolID:     poolID,
			ProviderID: provider.ID,
		}
		prs.poolPenalties[key] = p
	}
	wasBlacklisted := !p.BlacklistedUntil.IsZero() && time.Now().Before(p.BlacklistedUntil)
	if rule == nil {
		p.FailureCount++
	} else {
		if p.RuleFailureCounts == nil {
			p.RuleFailureCounts = make(map[string]int)
		}
		p.RuleFailureCounts[rule.ID]++
	}
	p.LastFailureAt = time.Now()
	p.LastReason = reason
	count := p.FailureCount
	if rule != nil {
		count = p.RuleFailureCounts[rule.ID]
		p.LastReason = rule.Name
	}

	if count >= threshold {
		p.BlacklistedUntil = time.Now().Add(time.Duration(durationMinutes) * time.Minute)
		penalty := *p
		prs.poolPenaltyMu.Unlock()
		if isAccountPool {
			// A blacklisted account key must not retain any sticky conversation
			// bindings. The store spans every relay key owned by this user because
			// blacklist state is pool-scoped rather than relay-key-scoped.
			prs.accountPoolStickyStore().invalidateProvider(userID, platform, poolID, provider.ID)
		}
		if !wasBlacklisted && prs.notificationService != nil {
			prs.notificationService.NotifyProviderBlacklistChanged(ProviderBlacklistChangedNotification{
				UserID:           penalty.UserID,
				Platform:         penalty.Platform,
				PoolID:           penalty.PoolID,
				ProviderID:       penalty.ProviderID,
				ProviderName:     provider.Name,
				Action:           "blacklisted",
				FailureCount:     penalty.FailureCount,
				LastFailureAt:    penalty.LastFailureAt,
				BlacklistedUntil: penalty.BlacklistedUntil,
				LastReason:       penalty.LastReason,
			})
		}
		return true
	}
	prs.poolPenaltyMu.Unlock()
	return false
}

// recordProviderFailure increments the consecutive failure count and, if the threshold
// is reached, blacklists the provider. Returns true when this failure resulted in a new
// blacklist.
func (prs *ProviderRelayService) recordProviderFailure(platform, poolID string, pool *ProviderPool, provider Provider, reason string) bool {
	return prs.recordProviderFailureForUser("", platform, poolID, pool, provider, reason)
}

// clearProviderBlacklistForUser manually removes the blacklist for a provider in a pool.
func (prs *ProviderRelayService) clearProviderBlacklistForUser(userID, platform, poolID string, providerID int64) {
	prs.poolPenaltyMu.Lock()
	key := penaltyKey(userID, platform, poolID, providerID)
	penalty, existed := prs.poolPenalties[key]
	wasBlacklisted := existed && !penalty.BlacklistedUntil.IsZero() && time.Now().Before(penalty.BlacklistedUntil)
	delete(prs.poolPenalties, key)
	prs.poolPenaltyMu.Unlock()

	if wasBlacklisted && prs.notificationService != nil {
		prs.notificationService.NotifyProviderBlacklistChanged(ProviderBlacklistChangedNotification{
			UserID:        strings.TrimSpace(userID),
			Platform:      platform,
			PoolID:        poolID,
			ProviderID:    providerID,
			Action:        "cleared",
			FailureCount:  penalty.FailureCount,
			LastFailureAt: penalty.LastFailureAt,
			LastReason:    penalty.LastReason,
		})
	}
}

// clearProviderBlacklist manually removes the blacklist for a provider in a pool.
func (prs *ProviderRelayService) clearProviderBlacklist(platform, poolID string, providerID int64) {
	prs.clearProviderBlacklistForUser("", platform, poolID, providerID)
}

// clearAllProviderBlacklistsForUser removes all active blacklist entries for a
// single user pool. It deliberately reuses clearProviderBlacklistForUser so
// every cleared provider emits the same blacklist-change notification as an
// individual manual clear.
func (prs *ProviderRelayService) clearAllProviderBlacklistsForUser(userID, platform, poolID string) {
	prefix := penaltyKeyPrefix(userID, platform, poolID)
	now := time.Now()

	prs.poolPenaltyMu.Lock()
	providerIDs := make([]int64, 0)
	for key, penalty := range prs.poolPenalties {
		if !strings.HasPrefix(key, prefix) || penalty == nil || penalty.BlacklistedUntil.IsZero() || !now.Before(penalty.BlacklistedUntil) {
			continue
		}
		providerIDs = append(providerIDs, penalty.ProviderID)
	}
	prs.poolPenaltyMu.Unlock()

	for _, providerID := range providerIDs {
		prs.clearProviderBlacklistForUser(userID, platform, poolID, providerID)
	}
}

// listProviderBlacklistStatusForUser returns penalty entries for providers that are
// currently blacklisted (BlacklistedUntil non-zero and not expired).
func (prs *ProviderRelayService) listProviderBlacklistStatusForUser(userID, platform, poolID string) []ProviderPoolProviderPenalty {
	validProviderIDs, filterStale := prs.providerIDsInPoolForUser(userID, platform, poolID)

	prs.poolPenaltyMu.Lock()
	defer prs.poolPenaltyMu.Unlock()
	now := time.Now()
	prefix := penaltyKeyPrefix(userID, platform, poolID)

	result := make([]ProviderPoolProviderPenalty, 0)
	for key, p := range prs.poolPenalties {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if filterStale {
			if _, ok := validProviderIDs[p.ProviderID]; !ok {
				delete(prs.poolPenalties, key)
				continue
			}
		}
		if p.BlacklistedUntil.IsZero() {
			continue
		}
		if now.After(p.BlacklistedUntil) {
			delete(prs.poolPenalties, key)
			continue
		}
		result = append(result, *p)
	}
	return result
}

// providerIDsInPoolForUser returns every provider identity still owned by the
// pool. SelectProvidersFromPool also supplies runtime-only providers, such as
// account-pool keys, while Members preserves disabled normal-pool members.
func (prs *ProviderRelayService) providerIDsInPoolForUser(userID, platform, poolID string) (map[int64]struct{}, bool) {
	if prs == nil || prs.poolService == nil {
		return nil, false
	}

	var (
		pool *ProviderPool
		err  error
	)
	if strings.TrimSpace(userID) != "" {
		pool, err = prs.poolService.ResolvePoolByIDForUser(userID, poolID)
	} else {
		pool, err = prs.poolService.ResolvePoolByID(poolID)
	}
	if err != nil || pool == nil || pool.Platform != platform {
		return nil, false
	}

	valid := make(map[int64]struct{}, len(pool.Members))
	for _, member := range pool.Members {
		valid[member.ProviderID] = struct{}{}
	}
	if normalizedProviderPoolType(pool.PoolType) != ProviderPoolTypeAccount {
		return valid, true
	}

	selected, err := SelectProvidersFromPool(pool, nil)
	if err != nil {
		return nil, false
	}
	for _, provider := range selected {
		valid[provider.ID] = struct{}{}
	}
	return valid, true
}

// listProviderBlacklistStatus returns penalty entries for providers that are
// currently blacklisted (BlacklistedUntil non-zero and not expired).
func (prs *ProviderRelayService) listProviderBlacklistStatus(platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatusForUser("", platform, poolID)
}

// selectProvidersForRequest 从请求上下文解析 pool
// 严格 fail-closed：只接受 relay key 的显式 pool binding
// - 有 binding 且 pool 存在且 platform 匹配：返回该 pool
// - 无 binding / pool 不存在 / platform 不匹配：返回 error
// 不回退默认池子，不回退旧 platform 逻辑
func (prs *ProviderRelayService) resolvePoolFromContext(c *gin.Context, kind string) (*ProviderPool, error) {
	bindings := relayKeyPoolBindingsFromContext(c)

	// 必须有显式 binding
	if bindings == nil {
		return nil, fmt.Errorf("relay key 未绑定任何池子")
	}

	poolID, ok := bindings[kind]
	if !ok || strings.TrimSpace(poolID) == "" {
		return nil, fmt.Errorf("relay key 未绑定 %s 的池子", kind)
	}

	userID := relayUserIDFromContext(c)
	var pool *ProviderPool
	var err error
	if strings.TrimSpace(userID) != "" {
		pool, err = prs.poolService.ResolvePoolByIDForUser(userID, poolID)
	} else {
		pool, err = prs.poolService.ResolvePoolByID(poolID)
	}
	if err != nil {
		return nil, fmt.Errorf("查找池子 %s 失败: %w", poolID, err)
	}
	if pool == nil {
		return nil, fmt.Errorf("relay key 绑定的池子 %s 不存在", poolID)
	}
	if pool.Platform != kind {
		return nil, fmt.Errorf("relay key 绑定的池子 %s 的 platform 不匹配（期望 %s，实际 %s）", poolID, kind, pool.Platform)
	}

	return pool, nil
}

// selectProvidersForRequest 根据池子选择供应商
// 这是 pool 模式下的统一入口，替代旧的 shouldRequireProviderEnabled + codexDirectAppliedProviderFilter
func (prs *ProviderRelayService) selectProvidersForRequestForUser(userID string, kind string, pool *ProviderPool, requestedModel string) ([]Provider, error) {
	if pool == nil {
		return nil, fmt.Errorf("%s 无可用池子", kind)
	}

	var providers []Provider
	var err error
	if strings.TrimSpace(userID) != "" {
		providers, err = prs.providerService.LoadProvidersForUser(userID, kind)
	} else {
		providers, err = prs.providerService.LoadProviders(kind)
	}
	if err != nil {
		return nil, fmt.Errorf("加载 %s providers 失败: %w", kind, err)
	}

	// 使用池子模式过滤供应商
	selected, err := SelectProvidersFromPool(pool, providers)
	if err != nil {
		return nil, err
	}

	// 对选中的供应商做进一步过滤
	active := make([]Provider, 0, len(selected))
	for _, provider := range selected {
		// 基础过滤：必须有 URL 和 Key
		if provider.APIURL == "" || provider.APIKey == "" {
			continue
		}

		// 配置验证
		if errs := provider.ValidateConfiguration(); len(errs) > 0 {
			fmt.Printf("[WARN] Provider %s 配置验证失败，已自动跳过: %v\n", provider.Name, errs)
			continue
		}

		// 模型支持过滤
		if requestedModel != "" && !provider.IsModelSupported(requestedModel) {
			fmt.Printf("[INFO] Provider %s 不支持模型 %s，已跳过\n", provider.Name, requestedModel)
			continue
		}

		active = append(active, provider)
	}

	return active, nil
}

func (prs *ProviderRelayService) selectProvidersForRequest(kind string, pool *ProviderPool, requestedModel string) ([]Provider, error) {
	return prs.selectProvidersForRequestForUser("", kind, pool, requestedModel)
}

func (prs *ProviderRelayService) buildProviderAttemptPlan(c *gin.Context, kind string, requestedModel string) (*providerAttemptPlan, bool, error) {
	pool, err := prs.resolvePoolFromContext(c, kind)
	if err != nil {
		return nil, false, err
	}

	userID := relayUserIDFromContext(c)
	active, err := prs.selectProvidersForRequestForUser(userID, kind, pool, requestedModel)
	if err != nil {
		return nil, true, err
	}

	poolID := pool.ID
	plan := &providerAttemptPlan{
		pool:   pool,
		userID: userID,
		poolID: poolID,
		active: active,
	}

	if pool.Mode == ProviderPoolModeManaged {
		beforeBlacklist := len(active)
		active = prs.filterBlacklistedProvidersForUser(userID, kind, poolID, active)
		plan.active = active
		plan.allBlacklisted = beforeBlacklist > 0 && len(active) == 0
	}

	levelGroups := make(map[int][]Provider)
	for _, provider := range active {
		level := getProviderLevelInPool(pool, provider)
		levelGroups[level] = append(levelGroups[level], provider)
	}

	levels := make([]int, 0, len(levelGroups))
	for level := range levelGroups {
		levels = append(levels, level)
	}
	sort.Ints(levels)

	plan.levelGroups = levelGroups
	plan.levels = levels
	return plan, true, nil
}

// EnsureDefaultPoolsAndBindings preserves the legacy default-pool migration
// for explicit migration and test callers. It is intentionally not invoked
// during normal startup: new deployments require users to create pools and
// relay-key bindings explicitly.
func (prs *ProviderRelayService) EnsureDefaultPoolsAndBindings() error {
	// 确定每个 platform 的当前模式
	platforms := []string{"claude", "openai-responses", "openai-chat"}
	seeds := make(map[string]DefaultPoolSeed)
	platformDefaults := make(map[string]string)

	for _, platform := range platforms {
		seed := DefaultPoolSeed{Mode: ProviderPoolModeManaged}

		// 根据当前托管状态推导模式
		if prs.shouldRequireProviderEnabled(platform) {
			// 托管模式
			seed.Mode = ProviderPoolModeManaged
		} else {
			// 手动模式（非托管）
			seed.Mode = ProviderPoolModeManual
			// 获取直接应用供应商
			directID, requiresDirect := prs.codexDirectAppliedProviderFilter(platform, false)
			if requiresDirect && directID != nil {
				seed.ManualProviderID = directID
			} else if requiresDirect {
				// 手动模式但无直接应用，记录警告
				fmt.Printf("[WARN] %s 手动模式无直接应用供应商，默认池子将无可用供应商\n", platform)
			}
		}

		seeds[platform] = seed
		platformDefaults[platform] = defaultPoolIDForPlatform(platform)
	}

	// 显式遗留迁移：为各平台补齐默认池。正常启动不调用此方法。
	if err := prs.poolService.EnsureDefaultPoolsForAllPlatforms(seeds); err != nil {
		fmt.Printf("[WARN] 确保默认池子失败: %v\n", err)
	}

	// relay key 绑定：只在一次性迁移时执行
	// NeedsMigration() 返回 true 表示 store version < 2，即从旧版本升级
	if prs.poolService.NeedsMigration() {
		fmt.Printf("[INFO] 执行一次性迁移：为现有 relay key 绑定默认池子\n")
		if err := prs.codexRelayKeys.EnsureDefaultPoolBindings(platformDefaults); err != nil {
			fmt.Printf("[WARN] 迁移绑定失败: %v\n", err)
		}
		if err := prs.poolService.MarkMigrationCompleted(); err != nil {
			fmt.Printf("[WARN] 标记迁移完成失败: %v\n", err)
		} else {
			fmt.Printf("[INFO] 迁移完成，后续启动不再自动绑定\n")
		}
	}

	return nil
}

// poolIDFromContext 从 gin.Context 获取 poolID
func poolIDFromContext(c *gin.Context) string {
	if c == nil {
		return ""
	}
	value, ok := c.Get(providerPoolIDContextKey)
	if !ok {
		return ""
	}
	id, ok := value.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(id)
}

func (prs *ProviderRelayService) Start() error {
	// 启动前验证配置
	if warnings := prs.validateConfig(); len(warnings) > 0 {
		fmt.Println("======== Provider 配置验证警告 ========")
		for _, warn := range warnings {
			fmt.Printf("⚠️  %s\n", warn)
		}
		fmt.Println("========================================")
	}

	router := gin.Default()
	router.Use(prs.trafficMiddleware())
	prs.registerRoutes(router)

	prs.server = &http.Server{
		Addr:    prs.addr,
		Handler: router,
	}

	fmt.Printf("provider relay server listening on %s\n", prs.addr)

	go func() {
		if err := prs.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("provider relay server error: %v\n", err)
		}
	}()
	return nil
}

// validateConfig 验证所有 provider 的配置
// 返回警告列表（非阻塞性错误）
func (prs *ProviderRelayService) validateConfig() []string {
	warnings := make([]string, 0)

	for _, kind := range []string{"claude", "openai-responses", "openai-chat"} {
		providers, err := prs.providerService.LoadProviders(kind)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("[%s] 加载配置失败: %v", kind, err))
			continue
		}

		enabledCount := 0
		for _, p := range providers {
			if !p.Enabled {
				continue
			}
			enabledCount++

			// 验证每个启用的 provider
			if errs := p.ValidateConfiguration(); len(errs) > 0 {
				for _, errMsg := range errs {
					warnings = append(warnings, fmt.Sprintf("[%s/%s] %s", kind, p.Name, errMsg))
				}
			}

			// 检查是否配置了模型白名单或映射
			if (p.SupportedModels == nil || len(p.SupportedModels) == 0) &&
				(p.ModelMapping == nil || len(p.ModelMapping) == 0) {
				warnings = append(warnings, fmt.Sprintf(
					"[%s/%s] 未配置 supportedModels 或 modelMapping，将假设支持所有模型（可能导致降级失败）",
					kind, p.Name))
			}

			// 检查是否只配置了映射但没有白名单
			if len(p.ModelMapping) > 0 && len(p.SupportedModels) == 0 {
				warnings = append(warnings, fmt.Sprintf(
					"[%s/%s] 配置了 modelMapping 但未配置 supportedModels，映射目标将不做校验，请确认目标模型在供应商处可用",
					kind, p.Name))
			}
		}

		if enabledCount == 0 {
			warnings = append(warnings, fmt.Sprintf("[%s] 没有启用的 provider", kind))
		}
	}

	return warnings
}

func (prs *ProviderRelayService) Stop() error {
	prs.proxyClientMu.Lock()
	for _, client := range prs.proxyClients {
		if client != nil {
			client.CloseIdleConnections()
		}
	}
	prs.proxyClients = make(map[string]*http.Client)
	prs.proxyClientLastUsed = make(map[string]time.Time)
	prs.proxyClientMu.Unlock()
	if prs.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return prs.server.Shutdown(ctx)
}

func (prs *ProviderRelayService) Addr() string {
	return prs.addr
}

func (prs *ProviderRelayService) registerRoutes(router gin.IRouter) {
	claudeAuth := prs.claudeRelayAuthMiddleware()
	codexAuth := prs.codexRelayAuthMiddleware()

	router.POST("/v1/messages", claudeAuth, prs.proxyHandler("claude", "/v1/messages"))
	router.POST("/v1/messages/count_tokens", claudeAuth, prs.proxyHandler("claude", "/v1/messages/count_tokens"))
	router.POST("/responses", codexAuth, prs.proxyHandler("openai-responses", "/responses"))
	router.POST("/v1/responses", codexAuth, prs.proxyHandler("openai-responses", "/v1/responses"))
	router.POST("/chat/completions", codexAuth, prs.proxyHandler("openai-chat", "/chat/completions"))
	router.POST("/v1/chat/completions", codexAuth, prs.proxyHandler("openai-chat", "/chat/completions"))

	// /v1/models 端点（OpenAI-compatible API）
	// 支持 Claude 和 Codex 平台
	router.GET("/v1/models", codexAuth, prs.modelsHandler(""))
	router.GET("/models", codexAuth, prs.modelsHandler(""))
}

func (prs *ProviderRelayService) resolveRelayEndpoint(kind string, provider Provider, routeEndpoint string) string {
	return provider.GetEffectiveEndpoint(routeEndpoint)
}

func (prs *ProviderRelayService) proxyHandler(kind string, endpoint string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if prs.concurrencyLimiter == nil {
			prs.concurrencyLimiter = NewProviderConcurrencyLimiter()
		}
		var bodyBytes []byte
		if c.Request.Body != nil {
			data, err := io.ReadAll(c.Request.Body)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
				return
			}
			bodyBytes = data
			c.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		isStream := gjson.GetBytes(bodyBytes, "stream").Bool()
		requestedModel := gjson.GetBytes(bodyBytes, "model").String()

		// 如果未指定模型，记录警告但不拦截
		if requestedModel == "" {
			fmt.Printf("[WARN] 请求未指定模型名，无法执行模型智能降级\n")
		}

		query := flattenQuery(c.Request.URL.Query())
		clientHeaders := cloneHeaders(c.Request.Header)

		var requestLog *ReqeustLog
		var queueItem *ProviderQueueItem
		var accountStickyRequest *accountPoolStickyRequest
		ensureRequestLog := func() *ReqeustLog {
			if requestLog == nil {
				requestLog = prs.startActiveRequestLog(c, kind, requestedModel, isStream)
			}
			return requestLog
		}
		defer func() {
			if accountStickyRequest != nil {
				prs.accountPoolStickyStore().abort(accountStickyRequest)
			}
			if requestLog != nil {
				prs.finishActiveRequestLog(requestLog)
			}
		}()

		totalAttempts := 0
		// A user-triggered retry deliberately re-enters pool selection instead
		// of pinning the previous provider. Account pools skip sticky ordering for
		// that one selection so the highest-priority available key is retried.
		retrySelectingPoolPriority := false
		for selectionRound := 0; ; selectionRound++ {
			if selectionRound > 0 {
				fmt.Printf("[INFO] 重新读取当前池子和 provider 配置\n")
			}
			if err := c.Request.Context().Err(); err != nil {
				if requestLog != nil {
					requestLog.HttpCode = 499
					requestLog.ErrorMessage = "client cancelled"
				}
				if queueItem != nil {
					prs.completeQueueWakeAndReserveNext(queueItem.UserID, queueItem.Platform, providerQueueKey(queueItem.UserID, queueItem.Platform, queueItem.PoolID), queueItem.RequestID)
				}
				return
			}

			plan, poolResolved, selectErr := prs.buildProviderAttemptPlan(c, kind, requestedModel)
			if selectErr != nil {
				if requestLog != nil {
					if !poolResolved {
						requestLog.HttpCode = http.StatusForbidden
					} else {
						requestLog.HttpCode = http.StatusNotFound
					}
					requestLog.ErrorMessage = selectErr.Error()
				}
				if queueItem != nil && prs.concurrencyLimiter != nil {
					prs.completeQueueWakeAndReserveNext(queueItem.UserID, queueItem.Platform, providerQueueKey(queueItem.UserID, queueItem.Platform, queueItem.PoolID), queueItem.RequestID)
				}
				if !poolResolved {
					fmt.Printf("[ERROR] 解析 %s 的池子失败: %v\n", kind, selectErr)
					c.JSON(http.StatusForbidden, gin.H{
						"error": fmt.Sprintf("relay key 无权访问 %s 的供应商池: %v", kind, selectErr),
					})
				} else {
					c.JSON(http.StatusNotFound, gin.H{"error": selectErr.Error()})
				}
				return
			}

			pool := plan.pool
			poolID := plan.poolID
			userID := plan.userID
			accountPool := isAccountPool(pool)
			if accountPool {
				if accountStickyRequest == nil {
					accountStickyRequest = prs.beginAccountPoolStickyRequest(c, plan, bodyBytes)
				}
				if !retrySelectingPoolPriority {
					prs.reorderAccountPoolAttemptPlan(plan, accountStickyRequest)
				}
			}
			// Every account-pool request is pinned to the provider selected for its
			// current attempt, including anonymous first requests that do not yet
			// have a durable sticky-session ID. It may move only after the selected
			// key becomes unavailable through blacklist or pool reconfiguration.
			strictAccountStickiness := accountPool && !retrySelectingPoolPriority && accountStickyRequest != nil && accountStickyRequest.providerID != 0
			requestContext := withProviderPoolContext(c.Request.Context(), pool, userID)
			if accountStickyRequest != nil {
				requestContext = withAccountPoolStickyRequestContext(requestContext, accountStickyRequest)
			}
			c.Request = c.Request.WithContext(requestContext)
			fmt.Printf("[INFO] 池子模式: %s/%s (模式: %s, 成员: %d)\n", kind, pool.Name, pool.Mode, len(pool.Members))

			if len(plan.active) == 0 {
				if queueItem != nil && prs.concurrencyLimiter != nil {
					prs.completeQueueWakeAndReserveNext(queueItem.UserID, queueItem.Platform, providerQueueKey(queueItem.UserID, queueItem.Platform, queueItem.PoolID), queueItem.RequestID)
				}
				if accountPool {
					currentLog := ensureRequestLog()
					currentLog.HttpCode = http.StatusServiceUnavailable
					currentLog.ErrorMessage = "号池暂无可用账号"
					c.JSON(http.StatusServiceUnavailable, gin.H{"error": "号池暂无可用账号，请稍后重试"})
					return
				}
				if plan.allBlacklisted {
					fmt.Printf("[WARN] 池子 %s 的所有 provider 均在拉黑期，无可用供应商\n", pool.Name)
					if requestLog != nil {
						requestLog.HttpCode = http.StatusServiceUnavailable
						requestLog.ErrorMessage = fmt.Sprintf("池子 %s 内所有 provider 均在临时拉黑期", pool.Name)
					}
					c.JSON(http.StatusServiceUnavailable, gin.H{
						"error": fmt.Sprintf("池子 %s 内所有 provider 均在临时拉黑期，请稍后重试或手动解除拉黑", pool.Name),
					})
					return
				}
				if requestLog != nil {
					requestLog.HttpCode = http.StatusNotFound
					requestLog.ErrorMessage = fmt.Sprintf("no providers available in pool %s/%s", kind, pool.Name)
				}
				if requestedModel != "" {
					c.JSON(http.StatusNotFound, gin.H{
						"error": fmt.Sprintf("没有可用的 provider 支持模型 '%s'（池子: %s/%s）", requestedModel, kind, pool.Name),
					})
				} else {
					c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no providers available in pool %s/%s", kind, pool.Name)})
				}
				return
			}

			currentLog := ensureRequestLog()
			queueKey := providerQueueKey(userID, kind, poolID)
			candidateProviders := providersFromAttemptPlan(plan)
			candidateProviderIDs := providerIDsFromProviders(candidateProviders)
			if queueItem != nil && queueItem.FlexibleProvider {
				prs.refreshFlexibleQueueReservation(userID, kind, currentLog.ActiveRequestID, candidateProviders)
			}
			if prs.concurrencyLimiter != nil && prs.concurrencyLimiter.HasQueueAhead(queueKey, currentLog.ActiveRequestID) {
				if queueItem == nil {
					queueItem = &ProviderQueueItem{
						RequestID:   currentLog.ActiveRequestID,
						UserID:      userID,
						Platform:    kind,
						PoolID:      poolID,
						Model:       requestedModel,
						Providers:   candidateProviders,
						ProviderIDs: candidateProviderIDs,
					}
				}
				refreshProviderQueueItem(queueItem, userID, kind, poolID, requestedModel, candidateProviders, candidateProviderIDs)
				fmt.Printf("[INFO] 池子 %s 已有等待队列，请求排到队尾\n", pool.Name)
				if !prs.waitForProviderQueueTurn(c, queueItem, currentLog, false, candidateProviders, false) {
					return
				}
				continue
			}

			fmt.Printf("[INFO] 池子 %s 找到 %d 个可用的 provider（拉黑过滤后）：", pool.Name, len(plan.active))
			for _, p := range plan.active {
				fmt.Printf("%s ", p.Name)
			}
			fmt.Println()

			c.Set("pool_mode", pool.Mode)
			c.Set("pool", pool)
			c.Set(providerPoolIDContextKey, poolID)

			fmt.Printf("[INFO] 共 %d 个 Level 分组：%v\n", len(plan.levels), plan.levels)
			fmt.Printf("[INFO] 🔄 降级模式（主 provider 粘性 + 自动拉黑切换）\n")

			reservedProviderID := int64(0)
			if prs.concurrencyLimiter != nil {
				if id, ok := prs.concurrencyLimiter.ReservedProviderForRequest(currentLog.ActiveRequestID); ok {
					reservedProviderID = id
					if !providerIDInProviders(candidateProviders, reservedProviderID) {
						fmt.Printf("[INFO] 保留的 provider %d 当前不可用，释放保留并重新选择 provider\n", reservedProviderID)
						prs.completeQueueWakeAndReserveNext(userID, kind, queueKey, currentLog.ActiveRequestID)
						reservedProviderID = 0
					}
				}
			}
			var lastError error
			var lastProvider string
			var lastDuration time.Duration
			stopOnStickyFailure := false
			retryRequested := false
			retryStrictAccountSelection := false
			sawConcurrencyFull := false

			for _, level := range plan.levels {
				providersInLevel := plan.levelGroups[level]

				fmt.Printf("[INFO] === 尝试 Level %d（%d 个 provider）===\n", level, len(providersInLevel))

				for i, provider := range providersInLevel {
					if reservedProviderID != 0 && provider.ID != reservedProviderID {
						continue
					}
					releaseSlot, acquired := prs.concurrencyLimiter.TryAcquireForRequest(userID, kind, provider, currentLog.ActiveRequestID)
					if !acquired {
						sawConcurrencyFull = true
						fmt.Printf("[INFO]   [%d/%d] Provider %s 并发已满（limit=%d），跳过当前 provider\n",
							i+1, len(providersInLevel), provider.Name, provider.NormalizedMaxConcurrency())
						continue
					}
					prs.completeQueueWakeAfterAcquire(userID, kind, queueKey, currentLog.ActiveRequestID, provider)
					slotReleased := false
					releaseProviderSlot := func(wake bool) {
						if slotReleased {
							return
						}
						slotReleased = true
						if releaseSlot != nil {
							for _, queueKey := range releaseSlot(wake) {
								prs.syncProviderQueuePositions(queueKey)
							}
						}
					}
					totalAttempts++

					// 获取实际应该使用的模型名
					effectiveModel := provider.GetEffectiveModel(requestedModel)

					// 如果需要映射，修改请求体
					currentBodyBytes := bodyBytes
					if effectiveModel != requestedModel && requestedModel != "" {
						fmt.Printf("[INFO] Provider %s 映射模型: %s -> %s\n", provider.Name, requestedModel, effectiveModel)

						modifiedBody, err := ReplaceModelInRequestBody(bodyBytes, effectiveModel)
						if err != nil {
							fmt.Printf("[ERROR] 替换模型名失败: %v\n", err)
							// 映射失败不应阻止尝试其他 provider
							releaseProviderSlot(true)
							continue
						}
						currentBodyBytes = modifiedBody
					}

					fmt.Printf("[INFO]   [%d/%d] Provider: %s | Model: %s\n", i+1, len(providersInLevel), provider.Name, effectiveModel)

					// 尝试发送请求
					// 获取有效的端点（用户配置优先）
					effectiveEndpoint := prs.resolveRelayEndpoint(kind, provider, endpoint)
					// The priority override applies until a replacement upstream attempt
					// actually starts. It must survive queueing and config reloads.
					retrySelectingPoolPriority = false
					startTime := time.Now()
					ok, err := false, error(nil)
					for preflightAttempt := 0; preflightAttempt < maxResponsesPreflightAttempts; preflightAttempt++ {
						ok, err = prs.forwardRequestWithLog(c, kind, provider, effectiveEndpoint, query, clientHeaders, currentBodyBytes, isStream, effectiveModel, currentLog)
						if ok || !shouldRetryResponsesPreflightFailure(kind, isStream, accountPool, c.Writer, err) || preflightAttempt+1 == maxResponsesPreflightAttempts {
							break
						}
						fmt.Printf("[WARN] Provider %s 在首个有效输出前结束 Responses 流，正在重试同一 provider\n", provider.Name)
						if waitBeforeResponsesPreflightRetry(c.Request.Context()) != nil {
							break
						}
					}
					duration := time.Since(startTime)
					if errors.Is(err, errActiveRequestRetryRequested) {
						fmt.Printf("[INFO] 用户触发重试，按当前池优先级重新选择 provider: Provider=%s | Model=%s\n", provider.Name, effectiveModel)
						releaseProviderSlot(true)
						retrySelectingPoolPriority = true
						retryRequested = true
						break
					}

					if ok {
						releaseProviderSlot(true)
						fmt.Printf("[INFO]   ✓ Level %d 成功: %s | 耗时: %.2fs\n", level, provider.Name, duration.Seconds())

						// 记录最后使用的供应商
						prs.setLastUsedProviderForUser(userID, kind, poolID, provider.Name)
						// 成功：清空该 provider 连续失败计数
						prs.recordProviderSuccessForUser(userID, kind, poolID, provider)

						return // 成功，立即返回
					}

					// 失败：记录错误并尝试下一个
					lastProvider = provider.Name
					lastDuration = duration

					errorMsg := "未知错误"
					if err != nil {
						errorMsg = redactProviderSecret(err.Error(), provider)
						if errorMsg == err.Error() {
							lastError = err
						} else {
							lastError = errors.New(errorMsg)
						}
					}
					if currentLog != nil {
						currentLog.ErrorMessage = redactProviderSecret(currentLog.ErrorMessage, provider)
					}
					fmt.Printf("[WARN]   ✗ Level %d 失败: %s | 错误: %s | 耗时: %.2fs\n",
						level, provider.Name, errorMsg, duration.Seconds())

					if errors.Is(err, errClientAbort) {
						fmt.Printf("[INFO] 客户端中断，停止重试: %s\n", provider.Name)
						releaseProviderSlot(true)
						return
					}
					if protocolErr, protocolFailure := protocolErrorFromError(err); protocolFailure && responseWriterWritten(c.Writer) {
						statusCode := currentLog.HttpCode
						errorBody := currentLog.ErrorMessage
						matchedRule := specialBlacklistRuleForFailure(pool, statusCode, errorBody)
						prs.recordPoolAttemptError(userID, pool, provider, statusCode, matchedRule, errorBody)
						prs.recordProviderFailureWithRuleForUser(userID, kind, poolID, pool, provider, protocolErr.code, matchedRule)
						fmt.Printf("[WARN] Provider %s 在客户端流已开始后出现协议错误，停止当前请求重试: %s\n", provider.Name, protocolErr.code)
						releaseProviderSlot(true)
						return
					}
					if proxyErr, proxyFailure := isProxyRequestError(err); proxyFailure {
						// A local Mihomo/listener failure says nothing about the
						// provider credential. Do not poison the provider blacklist.
						if prs.proxyManager != nil {
							prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
						}
						releaseProviderSlot(true)
						stopOnStickyFailure = true
						break
					}
					if accountPool {
						var clientErr *upstreamClientRequestError
						if errors.As(err, &clientErr) {
							// A deterministic request validation error is independent of
							// the selected account key. Returning it directly avoids
							// replaying the same invalid request through every key.
							if currentLog != nil {
								currentLog.HttpCode = clientErr.statusCode
								currentLog.ErrorMessage = summarizeBodyForError(string(clientErr.body), 1000)
							}
							prs.recordPoolAttemptError(userID, pool, provider, clientErr.statusCode, nil, clientErr.Error())
							releaseProviderSlot(true)
							writeUpstreamClientRequestError(c, clientErr)
							return
						}
					}
					statusCode := 0
					errorBody := ""
					if currentLog != nil {
						statusCode = currentLog.HttpCode
						errorBody = currentLog.ErrorMessage
					}
					matchedRule := specialBlacklistRuleForFailure(pool, statusCode, errorBody)
					attemptLogMessage := errorMsg
					if errorBody != "" {
						attemptLogMessage = errorBody
					}
					prs.recordPoolAttemptError(userID, pool, provider, statusCode, matchedRule, attemptLogMessage)
					failureReason := errorMsg
					if protocolErr, ok := protocolErrorFromError(err); ok {
						failureReason = protocolErr.code
					} else if matchedRule == nil && statusCode > 0 {
						failureReason = fmt.Sprintf("HTTP %d", statusCode)
					}

					// 每个实际 provider/key 尝试只向普通或高级拉黑机制提交一次失败。
					blacklistedAfterFailure := prs.recordProviderFailureWithRuleForUser(userID, kind, poolID, pool, provider, failureReason, matchedRule)
					if _, emptyStreamFailure := emptyStreamProtocolError(err); emptyStreamFailure && !blacklistedAfterFailure {
						// 空流是可重试的请求级协议故障，但不能在同一个逻辑请求中
						// 反复消耗全局失败阈值。未达到拉黑条件时直接把标准化
						// 502 返回客户端；后续独立请求可再次尝试这个粘性 key。
						releaseProviderSlot(true)
						stopOnStickyFailure = true
						break
					}
					if strictAccountStickiness {
						// Rebuild the attempt plan after every key failure. While the
						// sticky key remains available, order() keeps this request on
						// that key. Once it is blacklisted, the invalidated session is
						// rebound to the next available key before its next attempt.
						releaseProviderSlot(true)
						retryStrictAccountSelection = true
						break
					}

					if !blacklistedAfterFailure && !accountPool {
						fmt.Printf("[WARN] Provider %s 本次失败但未进入拉黑，保持为主 provider，停止继续切换\n", provider.Name)
						releaseProviderSlot(true)
						stopOnStickyFailure = true
						break
					}

					// 发送切换通知：仅在 provider 进入拉黑后，才切到下一个可用 provider
					if blacklistedAfterFailure && prs.notificationService != nil {
						nextProvider := nextProviderNameAfterIndex(plan.levels, plan.levelGroups, level, i)
						if nextProvider != "" {
							prs.notificationService.NotifyProviderSwitch(SwitchNotification{
								UserID:       userID,
								FromProvider: provider.Name,
								ToProvider:   nextProvider,
								Reason:       errorMsg,
								Platform:     kind,
							})
						}
					}
					releaseProviderSlot(true)
				}

				if retryRequested || retryStrictAccountSelection || stopOnStickyFailure {
					break
				}
				fmt.Printf("[WARN] Level %d 的所有 %d 个 provider 均失败，尝试下一 Level\n", level, len(providersInLevel))
			}

			if retryRequested || retryStrictAccountSelection {
				continue
			}

			if sawConcurrencyFull && !stopOnStickyFailure {
				if queueItem == nil {
					queueItem = &ProviderQueueItem{
						RequestID:   currentLog.ActiveRequestID,
						UserID:      userID,
						Platform:    kind,
						PoolID:      poolID,
						Model:       requestedModel,
						Providers:   candidateProviders,
						ProviderIDs: candidateProviderIDs,
					}
				}
				refreshProviderQueueItem(queueItem, userID, kind, poolID, requestedModel, candidateProviders, candidateProviderIDs)
				requeueFront := currentLog.Status == requestLogStatusQueued && currentLog.QueueKey == queueKey
				fmt.Printf("[INFO] 池子 %s 剩余候选 provider 并发已满，请求进入队列\n", pool.Name)
				if !prs.waitForProviderQueueTurn(c, queueItem, currentLog, requeueFront, candidateProviders, false) {
					return
				}
				continue
			}

			// 所有 provider 都失败，返回 502
			errorMsg := "未知错误"
			if lastError != nil {
				errorMsg = lastError.Error()
			}
			fmt.Printf("[ERROR] 所有 %d 个 provider 均失败，最后尝试: %s | 错误: %s\n",
				totalAttempts, lastProvider, errorMsg)

			if protocolErr, ok := protocolErrorFromError(lastError); ok {
				setRequestLogProtocolError(requestLog, protocolErr)
				writeUpstreamProtocolError(c, protocolErr)
				return
			}

			if accountPool {
				if _, proxyFailure := isProxyRequestError(lastError); !proxyFailure {
					if requestLog != nil {
						requestLog.HttpCode = http.StatusBadGateway
						requestLog.ErrorMessage = "号池中所有可用账号均请求失败"
					}
					c.JSON(http.StatusBadGateway, gin.H{"error": "号池中所有可用账号均请求失败，请稍后重试"})
					return
				}
			}

			if requestLog != nil {
				requestLog.HttpCode = http.StatusBadGateway
				requestLog.ErrorMessage = errorMsg
			}
			c.JSON(http.StatusBadGateway, gin.H{
				"error":          fmt.Sprintf("所有 %d 个 provider 均失败，最后错误: %s", totalAttempts, errorMsg),
				"last_provider":  lastProvider,
				"last_duration":  fmt.Sprintf("%.2fs", lastDuration.Seconds()),
				"total_attempts": totalAttempts,
			})
			return
		}
	}
}

func (prs *ProviderRelayService) startActiveRequestLog(c *gin.Context, kind string, model string, isStream bool) *ReqeustLog {
	start := time.Now()
	pool := providerPoolFromContext(c.Request.Context())
	requestLog := &ReqeustLog{
		Platform:                kind,
		Model:                   model,
		UserID:                  relayUserIDFromContext(c),
		IsStream:                isStream,
		RelayKeyID:              relayKeyIDFromContext(c),
		ClientIP:                clientIPFromRequest(c.Request),
		ExcludeFromTotalTraffic: isAccountPool(pool) && pool.ExcludeFromTotalTraffic,
		startedAt:               start,
	}
	requestLog.initializeTraffic(c)
	activeRequestID := defaultActiveRequestTracker.Start(requestLog, start)
	requestLog.ActiveRequestID = activeRequestID
	defaultActiveRequestTracker.Update(activeRequestID, requestLog)
	return requestLog
}

func (prs *ProviderRelayService) finishActiveRequestLog(requestLog *ReqeustLog) {
	if requestLog == nil {
		return
	}
	requestLog.finalizeClientTraffic()
	defaultActiveRequestTracker.Finish(requestLog.ActiveRequestID)
	if requestLog.attemptPersisted {
		return
	}
	prs.persistCompletedRequestLog(requestLog)
}

func (prs *ProviderRelayService) persistCompletedRequestLog(requestLog *ReqeustLog) {
	if requestLog == nil {
		return
	}
	if requestLog.startedAt.IsZero() {
		requestLog.startedAt = time.Now()
	}
	requestLog.DurationSec = time.Since(requestLog.startedAt).Seconds()

	if GlobalDBQueueLogs == nil {
		fmt.Printf("⚠️  写入 request_log 失败: 队列未初始化\n")
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	err := GlobalDBQueueLogs.ExecBatchCtx(ctx, `
		INSERT INTO request_log (
			user_id, platform, model, provider, relay_key_id, http_code,
			input_tokens, output_tokens, cache_create_tokens, cache_read_tokens,
			reasoning_tokens, is_stream, duration_sec, first_token_duration_sec, client_ip,
			upstream_header_sec, first_event_sec, first_text_sec, error_message, exclude_from_total,
			traffic_trace_id, client_network_scope, client_request_bytes, client_response_bytes,
			upstream_request_bytes, upstream_response_bytes, retry_request_bytes, retry_response_bytes,
			upstream_attempts, public_ingress_bytes, public_egress_bytes, local_ingress_bytes,
			local_egress_bytes, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		requestLog.UserID,
		requestLog.Platform,
		requestLog.Model,
		requestLog.Provider,
		requestLog.RelayKeyID,
		requestLog.HttpCode,
		requestLog.InputTokens,
		requestLog.OutputTokens,
		requestLog.CacheCreateTokens,
		requestLog.CacheReadTokens,
		requestLog.ReasoningTokens,
		boolToInt(requestLog.IsStream),
		requestLog.DurationSec,
		requestLog.FirstTokenDurationSec,
		requestLog.ClientIP,
		requestLog.UpstreamHeaderSec,
		requestLog.FirstEventSec,
		requestLog.FirstTextSec,
		requestLog.ErrorMessage,
		boolToInt(requestLog.ExcludeFromTotalTraffic),
		requestLog.TrafficTraceID,
		requestLog.ClientNetworkScope,
		requestLog.ClientRequestBytes,
		requestLog.ClientResponseBytes,
		requestLog.UpstreamRequestBytes,
		requestLog.UpstreamResponseBytes,
		requestLog.RetryRequestBytes,
		requestLog.RetryResponseBytes,
		requestLog.UpstreamAttempts,
		requestLog.PublicIngressBytes,
		requestLog.PublicEgressBytes,
		requestLog.LocalIngressBytes,
		requestLog.LocalEgressBytes,
		time.Now().UTC().Format(timeLayout),
	)

	if err != nil {
		fmt.Printf("写入 request_log 失败: %v\n", err)
	}
	RecordModelMonitorTraffic(requestLog)
}

func (prs *ProviderRelayService) persistFirstTextTimeoutAttempt(requestLog *ReqeustLog) {
	if requestLog == nil || requestLog.attemptPersisted {
		return
	}
	requestLog.HttpCode = http.StatusGatewayTimeout
	requestLog.ErrorMessage = firstTextTimeoutErrorBody
	completed := *requestLog
	completed.Status = requestLogStatusCompleted
	completed.RetryRequested = false
	completed.attemptPersisted = false
	prs.persistCompletedRequestLog(&completed)
	requestLog.attemptPersisted = true
	defaultActiveRequestTracker.MarkAttemptTransition(requestLog.ActiveRequestID, time.Now())
}

func (r *ReqeustLog) prepareProviderAttempt(c *gin.Context, kind string, provider Provider, model string, isStream bool) {
	if r == nil {
		return
	}
	r.Platform = kind
	r.Provider = provider.Name
	r.Model = model
	r.UserID = relayUserIDFromContext(c)
	r.IsStream = isStream
	r.RelayKeyID = relayKeyIDFromContext(c)
	r.ClientIP = clientIPFromRequest(c.Request)
	r.HttpCode = 0
	r.InputTokens = 0
	r.OutputTokens = 0
	r.CacheCreateTokens = 0
	r.CacheReadTokens = 0
	r.ReasoningTokens = 0
	r.UpstreamHeaderSec = 0
	r.FirstEventSec = 0
	r.FirstTextSec = 0
	r.FirstTokenDurationSec = 0
	r.ErrorMessage = ""
	r.Status = requestLogStatusProcessing
	r.RetryRequested = false
	r.QueuePosition = 0
	r.QueueStartedAt = ""
	r.QueueKey = ""
	r.inputTokensIncludeCacheRead = false
	r.attemptPersisted = false
	r.startedAt = time.Now()
}

func (prs *ProviderRelayService) syncProviderQueuePositions(queueKey string) {
	if prs == nil || prs.concurrencyLimiter == nil || strings.TrimSpace(queueKey) == "" {
		return
	}
	defaultActiveRequestTracker.UpdateQueuePositions(queueKey, prs.concurrencyLimiter.QueuePositions(queueKey))
}

func (prs *ProviderRelayService) wakeProviderQueuesForPlatform(userID, platform string) {
	if prs == nil || prs.concurrencyLimiter == nil {
		return
	}
	for _, queueKey := range prs.concurrencyLimiter.WakeQueuesForPlatform(userID, platform) {
		prs.syncProviderQueuePositions(queueKey)
	}
}

func (prs *ProviderRelayService) wakeProviderQueuesForProvider(userID, platform string, provider Provider) {
	if prs == nil || prs.concurrencyLimiter == nil {
		return
	}
	if provider.ID == 0 {
		prs.wakeProviderQueuesForPlatform(userID, platform)
		return
	}
	for _, queueKey := range prs.concurrencyLimiter.WakeQueueForProvider(userID, platform, provider) {
		prs.syncProviderQueuePositions(queueKey)
	}
}

func (prs *ProviderRelayService) wakeProviderQueuesForReservedProvider(userID, platform string, providerID int64) {
	if prs == nil || prs.concurrencyLimiter == nil || providerID == 0 {
		return
	}
	for _, queueKey := range prs.concurrencyLimiter.WakeQueueForReservedProvider(userID, platform, providerID) {
		prs.syncProviderQueuePositions(queueKey)
	}
}

func (prs *ProviderRelayService) wakeProviderQueuesForProviders(userID, platform string, providers []Provider) {
	if len(providers) == 0 {
		prs.wakeProviderQueuesForPlatform(userID, platform)
		return
	}
	for _, provider := range providers {
		prs.wakeProviderQueuesForProvider(userID, platform, provider)
	}
}

func (prs *ProviderRelayService) completeQueueWakeAndReserveNext(userID, platform, queueKey string, requestID int64) {
	if prs == nil || prs.concurrencyLimiter == nil || strings.TrimSpace(queueKey) == "" || requestID == 0 {
		return
	}
	for _, syncedQueueKey := range prs.concurrencyLimiter.CompleteWakeAndReserveNext(queueKey, requestID, userID, platform) {
		prs.syncProviderQueuePositions(syncedQueueKey)
	}
}

func (prs *ProviderRelayService) completeQueueWakeAfterAcquire(userID, platform, queueKey string, requestID int64, provider Provider) {
	if prs == nil || prs.concurrencyLimiter == nil || strings.TrimSpace(queueKey) == "" || requestID == 0 {
		return
	}
	for _, syncedQueueKey := range prs.concurrencyLimiter.CompleteWakeAfterAcquire(queueKey, requestID, userID, platform, provider) {
		prs.syncProviderQueuePositions(syncedQueueKey)
	}
}

func (prs *ProviderRelayService) refreshFlexibleQueueReservation(userID, platform string, requestID int64, providers []Provider) {
	if prs == nil || prs.concurrencyLimiter == nil || requestID == 0 || len(providers) == 0 {
		return
	}
	queueKeys, refreshed := prs.concurrencyLimiter.RefreshWokenProvidersForRequestAndReserveNext(requestID, providers, userID, platform)
	if refreshed {
		for _, queueKey := range queueKeys {
			prs.syncProviderQueuePositions(queueKey)
		}
	}
}

func refreshProviderQueueItem(item *ProviderQueueItem, userID, platform, poolID, model string, providers []Provider, providerIDs []int64) {
	if item == nil {
		return
	}
	item.UserID = userID
	item.Platform = platform
	item.PoolID = poolID
	item.Model = model
	item.Providers = providers
	item.ProviderIDs = providerIDs
}

func (prs *ProviderRelayService) waitForProviderQueueTurn(c *gin.Context, item *ProviderQueueItem, requestLog *ReqeustLog, front bool, wakeAfterEnqueueProviders []Provider, wakeAfterEnqueueAny bool) bool {
	if prs == nil || prs.concurrencyLimiter == nil || item == nil || requestLog == nil {
		return false
	}
	queueKey := providerQueueKey(item.UserID, item.Platform, item.PoolID)
	var position int
	var enqueueQueueKeys []string
	if front {
		position, enqueueQueueKeys = prs.concurrencyLimiter.EnqueueFrontWithHandoff(item)
	} else {
		position, enqueueQueueKeys = prs.concurrencyLimiter.EnqueueWithHandoff(item)
	}
	defaultActiveRequestTracker.MarkQueued(requestLog.ActiveRequestID, queueKey, position)
	requestLog.Status = requestLogStatusQueued
	requestLog.Provider = ""
	requestLog.QueueKey = queueKey
	requestLog.QueuePosition = position
	requestLog.ErrorMessage = "排队中"
	if requestLog.QueueStartedAt == "" {
		requestLog.QueueStartedAt = time.Now().In(beijingLocation).Format(timeLayout)
	}
	enqueueQueueKeys = appendStringUnique(enqueueQueueKeys, queueKey)
	for _, syncedQueueKey := range enqueueQueueKeys {
		prs.syncProviderQueuePositions(syncedQueueKey)
	}
	if len(wakeAfterEnqueueProviders) > 0 {
		prs.wakeProviderQueuesForProviders(item.UserID, item.Platform, wakeAfterEnqueueProviders)
	} else if wakeAfterEnqueueAny {
		prs.concurrencyLimiter.WakeQueue(item.UserID, item.Platform, item.PoolID)
		prs.syncProviderQueuePositions(queueKey)
	}

	select {
	case <-item.Ready:
		return true
	case <-c.Request.Context().Done():
		_, queueKeys := prs.concurrencyLimiter.RemoveQueuedAndReserveNext(item.RequestID, item.UserID, item.Platform)
		queueKeys = appendStringUnique(queueKeys, queueKey)
		for _, syncedQueueKey := range queueKeys {
			prs.syncProviderQueuePositions(syncedQueueKey)
		}
		requestLog.HttpCode = 499
		requestLog.ErrorMessage = "client cancelled while queued"
		return false
	}
}

func (prs *ProviderRelayService) forwardRequest(
	c *gin.Context,
	kind string,
	provider Provider,
	endpoint string,
	query url.Values,
	clientHeaders http.Header,
	bodyBytes []byte,
	isStream bool,
	model string,
) (bool, error) {
	requestLog := prs.startActiveRequestLog(c, kind, model, isStream)
	defer prs.finishActiveRequestLog(requestLog)
	return prs.forwardRequestWithLog(c, kind, provider, endpoint, query, clientHeaders, bodyBytes, isStream, model, requestLog)
}

func (prs *ProviderRelayService) forwardRequestWithLog(
	c *gin.Context,
	kind string,
	provider Provider,
	endpoint string,
	query url.Values,
	clientHeaders http.Header,
	bodyBytes []byte,
	isStream bool,
	model string,
	requestLog *ReqeustLog,
) (ok bool, err error) {
	targetURL := joinURL(provider.APIURL, endpoint)
	headers := cloneHeaders(clientHeaders)
	stripClientAddressHeadersForLocalRelay(headers, targetURL)

	// ========== count_tokens 本地估算（协议转换之前拦截）==========
	if kind == "claude" && strings.HasSuffix(endpoint, "/count_tokens") {
		supportsCountTokens := provider.SupportsCountTokens == nil || *provider.SupportsCountTokens
		if !supportsCountTokens {
			estimatedTokens := estimateInputTokens(bodyBytes)
			c.JSON(http.StatusOK, gin.H{
				"input_tokens": estimatedTokens,
			})
			return true, nil
		}
	}

	if kind == "openai-chat" && isStream {
		bodyBytes = ensureOpenAIChatStreamUsage(bodyBytes)
	}

	// Remove client-controlled Connection tokens before adding trusted provider
	// credentials. Otherwise `Connection: Authorization` could strip the header
	// after it has been injected below.
	removeHopByHopHeaders(headers)
	removeInboundAuthHeaders(headers)
	deleteHeaderCaseInsensitive(headers, "Accept-Encoding")

	// 根据认证方式设置请求头（默认 Bearer，与 v2.2.x 保持一致）
	authType := strings.ToLower(strings.TrimSpace(provider.ConnectivityAuthType))
	switch authType {
	case "x-api-key":
		// 仅当用户显式选择 x-api-key 时使用（Anthropic 官方 API）
		headers.Set("x-api-key", provider.APIKey)
		if kind == "claude" {
			headers.Set("anthropic-version", "2023-06-01")
		}
	case "", "bearer":
		// 默认使用 Bearer token（兼容所有第三方中转）
		headers.Set("Authorization", fmt.Sprintf("Bearer %s", provider.APIKey))
	default:
		// 自定义 Header 名
		headerName := strings.TrimSpace(provider.ConnectivityAuthType)
		if headerName == "" || strings.EqualFold(headerName, "custom") {
			headerName = "Authorization"
		}
		headers.Set(headerName, provider.APIKey)
	}

	if headers.Get("Accept") == "" {
		headers.Set("Accept", "application/json")
	}
	if isStream {
		deleteHeaderCaseInsensitive(headers, "Accept")
		deleteHeaderCaseInsensitive(headers, "Accept-Encoding")
		deleteHeaderCaseInsensitive(headers, "Content-Encoding")
		headers.Set("Accept", "text/event-stream")
		headers.Set("Accept-Encoding", "identity")
	}

	requestCtx, requestCancel := context.WithCancel(c.Request.Context())
	guardStreamingResponse := prs.shouldUseResponseStreamGuard(c, kind, endpoint)
	// A first-text deadline belongs to this direct provider/key attempt. A
	// local relay is no different from an external upstream here: if this pool
	// selected it, this pool owns its timeout and failure accounting. A nested
	// relay observes the resulting client disconnect independently.
	firstTextTimeoutOwnedByAttempt := guardStreamingResponse
	firstTextTimeout := time.Duration(0)
	startFirstTextAttempt := func(ctx context.Context) *providerRequestAttempt {
		return &providerRequestAttempt{ctx: ctx}
	}
	if requestLog == nil {
		requestLog = prs.startActiveRequestLog(c, kind, model, isStream)
		defer prs.finishActiveRequestLog(requestLog)
	}
	requestLog.prepareProviderAttempt(c, kind, provider, model, isStream)
	activeRequestID := requestLog.ActiveRequestID
	defer func() {
		if errors.Is(err, errCodexFirstTextTimeout) {
			prs.persistFirstTextTimeoutAttempt(requestLog)
		}
	}()
	if firstTextTimeoutOwnedByAttempt {
		firstTextTimeout = firstTextRetryTimeout(providerPoolFromContext(c.Request.Context()))
		if firstTextTimeout > 0 {
			startFirstTextAttempt = func(ctx context.Context) *providerRequestAttempt {
				// Proxy selection and local listener preparation do not belong to a
				// provider key. Start the deadline only when client.Do is about to send
				// the first upstream HTTP request for this attempt.
				startedAt := time.Now()
				requestLog.startedAt = startedAt
				defaultActiveRequestTracker.ResetAttemptStart(activeRequestID, requestLog, startedAt)
				attemptCtx, cancel := context.WithCancel(ctx)
				attempt := &providerRequestAttempt{
					ctx:       attemptCtx,
					startedAt: startedAt,
					cancel:    cancel,
				}
				timer := time.AfterFunc(firstTextTimeout, func() {
					attempt.timedOut.Store(true)
					cancel()
				})
				attempt.stopTimer = func() { timer.Stop() }
				return attempt
			}
		}
	}
	cancelGeneration := defaultActiveRequestTracker.BeginAttempt(activeRequestID, requestLog, requestCancel)
	defer func() {
		retryRequested := defaultActiveRequestTracker.UnregisterCancel(activeRequestID, cancelGeneration)
		requestCancel()
		if retryRequested && !errors.Is(err, errActiveRequestRetryRequested) && !errors.Is(err, errCodexFirstTextTimeout) {
			requestLog.markRetryRequested()
			ok = false
			err = errActiveRequestRetryRequested
		}
	}()
	trafficMetadata := &upstreamTrafficMetadata{
		service:    prs.trafficService,
		requestLog: requestLog,
		provider:   provider.Name,
		targetURL:  targetURL,
	}
	resp, firstTextAttempt, err := prs.doProviderRequestWithAttemptStart(requestCtx, targetURL, headers, query, bodyBytes, startFirstTextAttempt, trafficMetadata)
	if firstTextAttempt != nil {
		firstTextAttempt.stop()
		defer firstTextAttempt.close()
	}
	if firstTextAttempt != nil && firstTextAttempt.timedOut.Load() {
		if resp != nil && resp.RawResponse != nil && resp.RawResponse.Body != nil {
			_ = resp.RawResponse.Body.Close()
		}
		requestLog.HttpCode = http.StatusGatewayTimeout
		requestLog.ErrorMessage = firstTextTimeoutErrorBody
		return false, errCodexFirstTextTimeout
	}
	if err != nil && defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
		requestLog.markRetryRequested()
		return false, errActiveRequestRetryRequested
	}
	if err != nil && (requestCtx.Err() != nil || c.Request.Context().Err() != nil || errors.Is(err, context.Canceled)) {
		requestLog.HttpCode = 499
		requestLog.ErrorMessage = "client aborted"
		return false, fmt.Errorf("%w: %v", errClientAbort, err)
	}
	requestLog.markUpstreamHeaders()
	defaultActiveRequestTracker.Update(requestLog.ActiveRequestID, requestLog)
	remainingFirstTextTimeout := time.Duration(0)
	if firstTextTimeout > 0 && firstTextAttempt != nil && !firstTextAttempt.startedAt.IsZero() {
		remainingFirstTextTimeout = firstTextTimeout - time.Since(firstTextAttempt.startedAt)
		if remainingFirstTextTimeout <= 0 {
			if resp != nil && resp.RawResponse != nil && resp.RawResponse.Body != nil {
				_ = resp.RawResponse.Body.Close()
			}
			requestLog.HttpCode = http.StatusGatewayTimeout
			requestLog.ErrorMessage = firstTextTimeoutErrorBody
			return false, errCodexFirstTextTimeout
		}
	}

	// 无论成功失败，先尝试记录 HttpCode
	if resp != nil {
		requestLog.HttpCode = resp.StatusCode()
	}

	if err != nil {
		// resp 存在但 err != nil：可能是客户端中断，不计入失败
		if resp != nil && requestLog.HttpCode == 0 {
			fmt.Printf("[INFO] Provider %s 响应存在但状态码为0，判定为客户端中断\n", provider.Name)
			return false, fmt.Errorf("%w: %v", errClientAbort, err)
		}
		if resp != nil && isAccountPool(providerPoolFromContext(c.Request.Context())) && isRequestScopedUpstream4xx(resp.StatusCode()) {
			clientErr, readErr := newUpstreamClientRequestError(resp, provider)
			if readErr != nil {
				return false, readErr
			}
			requestLog.ErrorMessage = summarizeBodyForError(string(clientErr.body), 1000)
			return false, clientErr
		}
		// 尝试从响应体提取供应商原始错误信息
		if resp != nil {
			upstreamBody, extractErr := extractUpstreamError(resp)
			if extractErr != nil {
				return false, extractErr
			}
			if upstreamBody != "" {
				upstreamBody = redactProviderSecret(upstreamBody, provider)
				requestLog.ErrorMessage = summarizeBodyForError(upstreamBody, 1000)
				return false, fmt.Errorf("upstream status %d: %s", resp.StatusCode(), upstreamBody)
			}
		}
		requestLog.ErrorMessage = summarizeBodyForError(redactProviderSecret(err.Error(), provider), 1000)
		return false, err
	}

	if resp == nil {
		return false, fmt.Errorf("empty response")
	}

	status := requestLog.HttpCode

	if resp.Error() != nil {
		// resp 存在、有错误、但状态码为 0：客户端中断，不计入失败
		if status == 0 {
			fmt.Printf("[INFO] Provider %s 响应错误但状态码为0，判定为客户端中断\n", provider.Name)
			return false, fmt.Errorf("%w: %v", errClientAbort, resp.Error())
		}
		if isAccountPool(providerPoolFromContext(c.Request.Context())) && isRequestScopedUpstream4xx(status) {
			clientErr, readErr := newUpstreamClientRequestError(resp, provider)
			if readErr != nil {
				return false, readErr
			}
			requestLog.ErrorMessage = summarizeBodyForError(string(clientErr.body), 1000)
			return false, clientErr
		}
		// 优先使用 extractUpstreamError 提取完整错误（覆盖 SSE 空 body 场景）
		errMsg := strings.TrimSpace(resp.Error().Error())
		if errMsg == "" {
			upstreamBody, extractErr := extractUpstreamError(resp)
			if extractErr != nil {
				return false, extractErr
			}
			if upstreamBody != "" {
				errMsg = upstreamBody
			}
		}
		errMsg = redactProviderSecret(errMsg, provider)
		if errMsg != "" {
			requestLog.ErrorMessage = summarizeBodyForError(errMsg, 1000)
			return false, fmt.Errorf("upstream status %d: %s", status, errMsg)
		}
		requestLog.ErrorMessage = fmt.Sprintf("upstream status %d", status)
		return false, fmt.Errorf("upstream status %d", status)
	}

	// 状态码为 0 且无错误：当作成功处理
	if status == 0 {
		fmt.Printf("[WARN] Provider %s 返回状态码 0，但无错误，当作成功处理\n", provider.Name)
		var copyErr error
		if isStreamResponse(resp, isStream) {
			if prs.shouldUseResponseStreamGuard(c, kind, endpoint) {
				var responseWritten bool
				_, responseWritten, copyErr = writeCodexGuardedStreamingResponseWithOptions(c.Writer, resp, requestLog, prs.responseStreamGuardOptions(c, provider, remainingFirstTextTimeout), ReqeustLogHook(c, kind, requestLog))
				if firstTextAttempt != nil && firstTextAttempt.timedOut.Load() {
					requestLog.HttpCode = http.StatusGatewayTimeout
					requestLog.ErrorMessage = firstTextTimeoutErrorBody
					return false, errCodexFirstTextTimeout
				}
				if errors.Is(copyErr, errCodexFirstTextTimeout) {
					requestLog.HttpCode = http.StatusGatewayTimeout
					requestLog.ErrorMessage = firstTextTimeoutErrorBody
					return false, errCodexFirstTextTimeout
				}
				if copyErr != nil && (requestCtx.Err() != nil || c.Request.Context().Err() != nil || errors.Is(copyErr, context.Canceled)) {
					if streamDeliveredFirstText(responseWritten, requestLog) {
						logLateStreamClientClose(provider, copyErr)
						return true, nil
					}
					requestLog.HttpCode = 499
					requestLog.ErrorMessage = "client aborted"
					return false, fmt.Errorf("%w: %v", errClientAbort, copyErr)
				}
				if copyErr != nil && !responseWritten {
					if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
						requestLog.markRetryRequested()
						return false, errActiveRequestRetryRequested
					}
					protocolErr := newCodexStreamPreflightProtocolError(status, copyErr)
					setRequestLogProtocolError(requestLog, protocolErr)
					return false, protocolErr
				}
				if protocolErr := committedCodexStreamProtocolError(status, responseWritten, copyErr, requestLog); protocolErr != nil {
					return false, protocolErr
				}
			} else {
				_, copyErr = writeStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
			}
		} else if kind == "openai-chat" {
			copyErr = writeOpenAIChatJSONResponse(c.Writer, resp, requestLog)
		} else {
			defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
			_, copyErr = resp.ToHttpResponseWriter(c.Writer, ReqeustLogHook(c, kind, requestLog))
		}
		if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
			requestLog.markRetryRequested()
			return false, errActiveRequestRetryRequested
		}
		if copyErr != nil {
			fmt.Printf("[WARN] 复制响应到客户端失败（不影响provider成功判定）: %v\n", copyErr)
		}
		return true, nil
	}

	if status >= http.StatusOK && status < http.StatusMultipleChoices {
		if isStream {
			if err := upstreamHTMLStreamError(resp); err != nil {
				protocolErr := newInvalidStreamContentTypeProtocolError(status, err)
				setRequestLogProtocolError(requestLog, protocolErr)
				return false, protocolErr
			}
		}

		// 非流式：先读取响应体，解析 token 和内容，确认非空壳后再写给客户端
		if !isStream && !isStreamResponse(resp, isStream) {
			bodyData, readErr := readResponseBodyWithFirstTextTimeout(resp, remainingFirstTextTimeout)
			if readErr != nil {
				if errors.Is(readErr, errCodexFirstTextTimeout) {
					requestLog.HttpCode = http.StatusGatewayTimeout
					requestLog.ErrorMessage = firstTextTimeoutErrorBody
					return false, errCodexFirstTextTimeout
				}
				if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
					requestLog.markRetryRequested()
					return false, errActiveRequestRetryRequested
				}
				if requestCtx.Err() != nil || c.Request.Context().Err() != nil || errors.Is(readErr, context.Canceled) {
					requestLog.HttpCode = 499
					requestLog.ErrorMessage = "client aborted"
					return false, fmt.Errorf("%w: %v", errClientAbort, readErr)
				}
				return false, fmt.Errorf("failed to read response body: %w", readErr)
			}

			// 按路径解析 token 和内容，并准备最终要写的 body
			finalBody := bodyData
			contentType := resp.RawResponse.Header.Get("Content-Type")

			if kind == "openai-chat" {
				// OpenAI Chat：使用正确的 prompt_tokens/completion_tokens 解析
				OpenAIChatParseTokenUsageFromResponse(string(bodyData), requestLog)
				if contentType == "" {
					contentType = "application/json"
				}
			} else if kind == "openai-responses" {
				// OpenAI Responses：解析嵌套缓存/推理字段
				CodexParseTokenUsageFromResponse(string(bodyData), requestLog)
				if contentType == "" {
					contentType = "application/json"
				}
			} else {
				// 通用格式（Anthropic 等）
				parseNonStreamingTokens(bodyData, kind, requestLog)
			}

			// 空壳检测
			if requestLog.isEmptyShell() && !hasContentInResponse(finalBody, kind) {
				fmt.Printf("[WARN] Provider %s 返回 200 空壳响应（无 tokens 且无内容），计为失败\n", provider.Name)
				return false, fmt.Errorf("%w: provider %s returned 200 empty shell", errProviderEmptyShell, provider.Name)
			}
			requestLog.markFirstText()

			// 非空壳：复制响应头并写给客户端
			copyResponseHeaders(c.Writer, resp.RawResponse.Header)
			if contentType != "" {
				c.Writer.Header().Set("Content-Type", contentType)
			}
			c.Writer.Header().Del("Content-Length")
			if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
				requestLog.markRetryRequested()
				return false, errActiveRequestRetryRequested
			}
			if kind == "openai-responses" {
				prs.commitAccountPoolStickyResponse(c, provider, gjson.GetBytes(finalBody, "id").String())
			}
			defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
			c.Writer.WriteHeader(status)
			if _, writeErr := c.Writer.Write(finalBody); writeErr != nil {
				fmt.Printf("[WARN] 复制响应到客户端失败: %v\n", writeErr)
			}
			return true, nil
		}

		var copyErr error
		if isStreamResponse(resp, isStream) {
			if prs.shouldUseResponseStreamGuard(c, kind, endpoint) {
				var responseWritten bool
				_, responseWritten, copyErr = writeCodexGuardedStreamingResponseWithOptions(c.Writer, resp, requestLog, prs.responseStreamGuardOptions(c, provider, remainingFirstTextTimeout), ReqeustLogHook(c, kind, requestLog))
				if firstTextAttempt != nil && firstTextAttempt.timedOut.Load() {
					requestLog.HttpCode = http.StatusGatewayTimeout
					requestLog.ErrorMessage = firstTextTimeoutErrorBody
					return false, errCodexFirstTextTimeout
				}
				if errors.Is(copyErr, errCodexFirstTextTimeout) {
					requestLog.HttpCode = http.StatusGatewayTimeout
					requestLog.ErrorMessage = firstTextTimeoutErrorBody
					return false, errCodexFirstTextTimeout
				}
				if copyErr != nil && (requestCtx.Err() != nil || c.Request.Context().Err() != nil || errors.Is(copyErr, context.Canceled)) {
					if streamDeliveredFirstText(responseWritten, requestLog) {
						logLateStreamClientClose(provider, copyErr)
						return true, nil
					}
					requestLog.HttpCode = 499
					requestLog.ErrorMessage = "client aborted"
					return false, fmt.Errorf("%w: %v", errClientAbort, copyErr)
				}
				if copyErr != nil && !responseWritten {
					if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
						requestLog.markRetryRequested()
						return false, errActiveRequestRetryRequested
					}
					protocolErr := newCodexStreamPreflightProtocolError(status, copyErr)
					setRequestLogProtocolError(requestLog, protocolErr)
					return false, protocolErr
				}
				if protocolErr := committedCodexStreamProtocolError(status, responseWritten, copyErr, requestLog); protocolErr != nil {
					return false, protocolErr
				}
			} else {
				_, copyErr = writeStreamingResponse(c.Writer, resp, requestLog, ReqeustLogHook(c, kind, requestLog))
			}
		} else if kind == "openai-chat" {
			copyErr = writeOpenAIChatJSONResponse(c.Writer, resp, requestLog)
		} else {
			defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
			_, copyErr = resp.ToHttpResponseWriter(c.Writer, ReqeustLogHook(c, kind, requestLog))
		}
		if defaultActiveRequestTracker.IsRetryRequested(activeRequestID) {
			requestLog.markRetryRequested()
			return false, errActiveRequestRetryRequested
		}
		if copyErr != nil {
			fmt.Printf("[WARN] 复制响应到客户端失败（不影响provider成功判定）: %v\n", copyErr)
		}
		// 只要provider返回了2xx状态码，就算成功（复制失败是客户端问题，不是provider问题）
		return true, nil
	}

	if isAccountPool(providerPoolFromContext(c.Request.Context())) && isRequestScopedUpstream4xx(status) {
		clientErr, readErr := newUpstreamClientRequestError(resp, provider)
		if readErr != nil {
			return false, readErr
		}
		requestLog.ErrorMessage = summarizeBodyForError(string(clientErr.body), 1000)
		return false, clientErr
	}

	// 尝试从响应体提取供应商原始错误信息
	upstreamBody, extractErr := extractUpstreamError(resp)
	if extractErr != nil {
		return false, extractErr
	}
	if upstreamBody != "" {
		requestLog.ErrorMessage = summarizeBodyForError(upstreamBody, 1000)
		return false, fmt.Errorf("upstream status %d: %s", status, upstreamBody)
	}
	requestLog.ErrorMessage = fmt.Sprintf("upstream status %d", status)
	return false, fmt.Errorf("upstream status %d", status)
}

func (prs *ProviderRelayService) doProviderRequest(ctx context.Context, targetURL string, headers http.Header, query url.Values, bodyBytes []byte) (*xrequest.Response, error) {
	response, _, err := prs.doProviderRequestWithAttemptStart(ctx, targetURL, headers, query, bodyBytes, nil, nil)
	return response, err
}

func (prs *ProviderRelayService) doProviderRequestWithAttemptStart(
	ctx context.Context,
	targetURL string,
	headers http.Header,
	query url.Values,
	bodyBytes []byte,
	startAttempt func(context.Context) *providerRequestAttempt,
	trafficMetadata ...*upstreamTrafficMetadata,
) (*xrequest.Response, *providerRequestAttempt, error) {
	const maxAttempts = 2
	var lastErr error
	var traffic *upstreamTrafficMetadata
	if len(trafficMetadata) > 0 {
		traffic = trafficMetadata[0]
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		client, endpoint, clientErr := prs.requestClient(ctx)
		if clientErr != nil {
			lastErr = clientErr
			if proxyErr, ok := isProxyRequestError(clientErr); ok {
				prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
			}
			if _, ok := isProxyRequestError(clientErr); ok && attempt+1 < maxAttempts {
				continue
			}
			return nil, nil, clientErr
		}

		var requestAttempt *providerRequestAttempt
		requestCtx := ctx
		if startAttempt != nil {
			requestAttempt = startAttempt(ctx)
			if requestAttempt != nil && requestAttempt.ctx != nil {
				requestCtx = requestAttempt.ctx
			}
		}
		req, err := newProviderHTTPRequest(requestCtx, targetURL, headers, query, bodyBytes)
		if err != nil {
			requestAttempt.close()
			return nil, requestAttempt, err
		}

		trafficAttempt := traffic.begin()
		trafficAttempt.wrapRequest(req)
		resp, err := client.Do(req)
		trafficAttempt.wrapResponse(resp)
		if err != nil {
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
			trafficAttempt.finish()
			lastErr = err
			timedOut := requestAttempt != nil && requestAttempt.timedOut.Load()
			requestAttempt.close()
			if timedOut {
				return nil, requestAttempt, err
			}
			if proxyErr, ok := isProxyRequestError(err); ok {
				prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
			}
			if attempt+1 < maxAttempts && waitBeforeProviderRetry(ctx) == nil {
				continue
			}
			return nil, requestAttempt, err
		}
		prs.recordResponsesCloudflareBlock(requestCtx, endpoint, targetURL, resp)
		if requestAttempt != nil && requestAttempt.timedOut.Load() {
			_ = resp.Body.Close()
			requestAttempt.close()
			return nil, requestAttempt, context.Canceled
		}
		if resp != nil && resp.StatusCode >= http.StatusInternalServerError && attempt+1 < maxAttempts {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			requestAttempt.close()
			if waitBeforeProviderRetry(ctx) == nil {
				continue
			}
		}

		return xrequest.NewResponse(resp), requestAttempt, nil
	}

	if lastErr != nil {
		return nil, nil, lastErr
	}
	return nil, nil, fmt.Errorf("provider request failed")
}

func newProviderHTTPRequest(ctx context.Context, targetURL string, headers http.Header, query url.Values, bodyBytes []byte) (*http.Request, error) {
	requestURL, err := addQueryParams(targetURL, query)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.ContentLength = int64(len(bodyBytes))
	forwardHeaders := cloneHeaders(headers)
	removeHopByHopHeaders(forwardHeaders)
	for key, values := range forwardHeaders {
		if strings.TrimSpace(key) == "" {
			continue
		}
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	return req, nil
}

func addQueryParams(targetURL string, query url.Values) (string, error) {
	if len(query) == 0 {
		return targetURL, nil
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return "", err
	}
	values := parsed.Query()
	for key, valuesForKey := range query {
		if strings.TrimSpace(key) == "" {
			continue
		}
		values.Del(key)
		for _, value := range valuesForKey {
			values.Add(key, value)
		}
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func appendRawQuery(targetURL, rawQuery string) string {
	if rawQuery == "" {
		return targetURL
	}
	fragment := ""
	if index := strings.IndexByte(targetURL, '#'); index >= 0 {
		fragment = targetURL[index:]
		targetURL = targetURL[:index]
	}
	separator := "?"
	if strings.Contains(targetURL, "?") {
		if strings.HasSuffix(targetURL, "?") || strings.HasSuffix(targetURL, "&") {
			separator = ""
		} else {
			separator = "&"
		}
	}
	return targetURL + separator + rawQuery + fragment
}

func waitBeforeProviderRetry(ctx context.Context) error {
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func codexStreamPreflightFailureReason(err error) string {
	if errors.Is(err, errCodexFirstTextTimeout) {
		return "HTTP 504 (first text timeout)"
	}
	return "codex empty stream"
}

func codexStreamPreflightFailureBody(err error) string {
	if errors.Is(err, errCodexFirstTextTimeout) {
		return firstTextTimeoutErrorBody
	}
	return ""
}

func (prs *ProviderRelayService) recordCodexStreamPreflightFailureForUser(userID, kind, poolID string, pool *ProviderPool, provider Provider, err error) bool {
	reason := codexStreamPreflightFailureReason(err)
	errorBody := codexStreamPreflightFailureBody(err)
	statusCode := 0
	if errors.Is(err, errCodexFirstTextTimeout) {
		statusCode = http.StatusGatewayTimeout
	}
	matchedRule := specialBlacklistRuleForFailure(pool, statusCode, errorBody)
	logBody := errorBody
	if logBody == "" {
		logBody = reason
	}
	prs.recordPoolAttemptError(userID, pool, provider, statusCode, matchedRule, logBody)
	return prs.recordProviderFailureWithRuleForUser(userID, kind, poolID, pool, provider, reason, matchedRule)
}

func isResponsesEndpoint(endpoint string) bool {
	return strings.Contains(strings.ToLower(endpoint), "/responses")
}

func isStreamResponse(resp *xrequest.Response, requestedStream bool) bool {
	if requestedStream {
		return true
	}
	if resp == nil || resp.RawResponse == nil {
		return false
	}
	return strings.Contains(strings.ToLower(resp.RawResponse.Header.Get("Content-Type")), "text/event-stream")
}

// streamDeliveredFirstText distinguishes a real response from the guard's
// initial keepalive. A client may normally close an SSE connection after it
// has consumed response.completed; that late close must not turn an already
// delivered response into a synthetic 499 in the Logs page.
func streamDeliveredFirstText(responseWritten bool, requestLog *ReqeustLog) bool {
	return responseWritten && requestLog != nil && requestLog.FirstTextSec > 0
}

func logLateStreamClientClose(provider Provider, copyErr error) {
	if copyErr == nil {
		return
	}
	message := redactProviderSecret(copyErr.Error(), provider)
	fmt.Printf("[INFO] 客户端在首字后关闭流，保留供应商成功结果: %s | %s\n", provider.Name, message)
}

func upstreamHTMLStreamError(resp *xrequest.Response) error {
	if resp == nil || resp.RawResponse == nil {
		return nil
	}
	contentType := strings.ToLower(resp.RawResponse.Header.Get("Content-Type"))
	if !strings.Contains(contentType, "text/html") {
		return nil
	}
	rawBody, extractErr := extractUpstreamError(resp)
	if extractErr != nil {
		return extractErr
	}
	body := summarizeBodyForError(rawBody, 240)
	if body == "" {
		return fmt.Errorf("upstream returned HTML instead of SSE")
	}
	return fmt.Errorf("upstream returned HTML instead of SSE: %s", body)
}

func summarizeBodyForError(body string, maxLen int) string {
	body = strings.Join(strings.Fields(body), " ")
	if maxLen <= 0 || len(body) <= maxLen {
		return body
	}
	return body[:maxLen] + "..."
}

func redactProviderSecret(value string, provider Provider) string {
	if !isValidAccountPoolKeyID(provider.ID) {
		return value
	}
	secrets := []string{provider.APIKey, strings.TrimSpace(provider.APIKey)}
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		value = strings.ReplaceAll(value, secret, "[REDACTED]")
	}
	return value
}

func writeStreamingResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	if resp == nil || resp.RawResponse == nil {
		return 0, fmt.Errorf("empty upstream response")
	}

	raw := resp.RawResponse
	if raw.Body != nil {
		defer raw.Body.Close()
	}

	copyStreamingResponseHeaders(w.Header(), raw.Header)
	normalizeStreamingResponseHeaders(w.Header())
	status := resp.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	if requestLog != nil {
		defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
	}
	w.WriteHeader(status)

	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}

	if raw.Body == nil {
		return 0, nil
	}

	reader := bufio.NewReader(raw.Body)
	totalBytes := int64(0)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			n, writeErr := writeStreamingLine(w, line, requestLog, hooks...)
			totalBytes += n
			if writeErr != nil {
				return totalBytes, writeErr
			}
		}

		if err != nil {
			if err == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, fmt.Errorf("error streaming response: %w", err)
		}
	}
}

const (
	codexStreamGuardMaxInitialBufferBytes = 1024 * 1024
	codexStreamGuardKeepAliveInterval     = 15 * time.Second
)

var codexStreamGuardKeepAliveComment = ":" + strings.Repeat(" ", 1024) + "\n\n"

type codexStreamGuardState struct {
	sawCompleted     bool
	sawFailed        bool
	sawIncomplete    bool
	sawUsefulContent bool
	responseID       string
}

func (s *codexStreamGuardState) observeLine(line []byte) {
	trimmed := strings.TrimSpace(string(line))
	if !strings.HasPrefix(trimmed, "data:") {
		return
	}
	data := strings.TrimSpace(strings.TrimPrefix(trimmed, "data:"))
	if data == "" || data == "[DONE]" || !json.Valid([]byte(data)) {
		return
	}

	eventType := gjson.Get(data, "type").String()
	switch eventType {
	case "response.completed":
		s.sawCompleted = true
		if responsesOutputHasUsefulContent(gjson.Get(data, "response.output")) {
			s.sawUsefulContent = true
		}
	case "response.failed":
		s.sawFailed = true
	case "response.incomplete":
		s.sawIncomplete = true
	case "response.output_text.delta", "response.output_text.done",
		"response.function_call_arguments.delta", "response.function_call_arguments.done",
		"response.reasoning_summary_text.delta", "response.reasoning_summary_text.done",
		"response.reasoning_text.delta", "response.reasoning_text.done":
		if strings.TrimSpace(gjson.Get(data, "delta").String()) != "" || strings.TrimSpace(gjson.Get(data, "text").String()) != "" || strings.TrimSpace(gjson.Get(data, "arguments").String()) != "" {
			s.sawUsefulContent = true
		}
	case "response.output_item.added", "response.output_item.done":
		if responseOutputItemHasUsefulContent(gjson.Get(data, "item"), eventType == "response.output_item.done") {
			s.sawUsefulContent = true
		}
	}
	if responseID := strings.TrimSpace(gjson.Get(data, "response.id").String()); responseID != "" {
		s.responseID = responseID
	}

}

func (s codexStreamGuardState) completedSuccessfully() bool {
	return s.sawUsefulContent && s.sawCompleted && !s.sawFailed && !s.sawIncomplete && strings.TrimSpace(s.responseID) != ""
}

func responsesOutputHasUsefulContent(output gjson.Result) bool {
	if !output.IsArray() {
		return false
	}
	for _, item := range output.Array() {
		if responseOutputItemHasUsefulContent(item, true) {
			return true
		}
	}
	return false
}

func responseOutputItemHasUsefulContent(item gjson.Result, final bool) bool {
	switch item.Get("type").String() {
	case "message":
		for _, content := range item.Get("content").Array() {
			if strings.TrimSpace(content.Get("text").String()) != "" || strings.TrimSpace(content.Get("refusal").String()) != "" {
				return true
			}
		}
		return false
	case "reasoning":
		for _, summary := range item.Get("summary").Array() {
			if strings.TrimSpace(summary.Get("text").String()) != "" {
				return true
			}
		}
		for _, content := range item.Get("content").Array() {
			if strings.TrimSpace(content.Get("text").String()) != "" {
				return true
			}
		}
		return strings.TrimSpace(item.Get("encrypted_content").String()) != ""
	case "function_call":
		return true
	case "custom_tool_call":
		return true
	case "local_shell_call", "computer_call", "web_search_call", "file_search_call", "code_interpreter_call", "mcp_call":
		return true
	case "image_generation_call":
		return final && (strings.TrimSpace(item.Get("result").String()) != "" || strings.TrimSpace(item.Get("revised_prompt").String()) != "" || strings.EqualFold(item.Get("status").String(), "completed"))
	case "compaction", "compaction_summary":
		return strings.TrimSpace(item.Get("encrypted_content").String()) != ""
	case "ghost_snapshot":
		return item.Get("ghost_commit").Exists()
	default:
		// A completed output item is model output even when this relay does not
		// yet know its concrete schema. Keep added/partial items conservative so
		// metadata placeholders cannot prematurely commit HTTP 200.
		return final && strings.TrimSpace(item.Get("type").String()) != ""
	}
}

type codexStreamGuardOptions struct {
	deferInitialKeepAlive        bool
	disableKeepAliveUntilRelease bool
	firstUsefulContentTimeout    time.Duration
	keepAliveInterval            time.Duration
	onSuccessfulCompleted        func(responseID string)
}

func writeCodexGuardedStreamingResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, bool, error) {
	return writeCodexGuardedStreamingResponseWithOptions(
		w,
		resp,
		requestLog,
		codexStreamGuardOptions{
			deferInitialKeepAlive:        true,
			disableKeepAliveUntilRelease: true,
		},
		hooks...,
	)
}

func writeCodexGuardedStreamingResponseWithOptions(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog, options codexStreamGuardOptions, hooks ...xrequest.ResponseHook) (int64, bool, error) {
	if resp == nil || resp.RawResponse == nil {
		return 0, false, fmt.Errorf("empty upstream response")
	}

	raw := resp.RawResponse
	if raw.Body != nil {
		defer raw.Body.Close()
	}
	if raw.Body == nil {
		return 0, false, errCodexEmptyStream
	}

	var writeMu sync.Mutex
	clientStarted := responseWriterWritten(w)
	released := false
	eventBoundary := true
	var preflightReleased atomic.Bool
	var firstUsefulContentTimedOut atomic.Bool
	var terminalEventSeen atomic.Bool
	totalBytes := int64(0)
	state := codexStreamGuardState{}
	completionCommitted := false
	var initialBuffer bytes.Buffer

	writeHeaderLocked := func() {
		if clientStarted {
			return
		}
		copyStreamingResponseHeaders(w.Header(), raw.Header)
		normalizeStreamingResponseHeaders(w.Header())
		status := resp.StatusCode()
		if status == 0 {
			status = http.StatusOK
		}
		if requestLog != nil {
			defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
		}
		w.WriteHeader(status)
		clientStarted = true
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
	}

	sendKeepAliveLocked := func() error {
		if terminalEventSeen.Load() || (!released && options.disableKeepAliveUntilRelease) || (released && !eventBoundary) {
			return nil
		}
		writeHeaderLocked()
		if _, err := io.WriteString(w, codexStreamGuardKeepAliveComment); err != nil {
			return fmt.Errorf("error writing codex stream keepalive: %w", err)
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		return nil
	}

	flushInitialBuffer := func() error {
		writeMu.Lock()
		defer writeMu.Unlock()
		preflightReleased.Store(true)
		released = true
		writeHeaderLocked()
		if initialBuffer.Len() == 0 {
			return nil
		}
		n, err := writeStreamingBuffer(w, initialBuffer.Bytes(), requestLog, hooks...)
		totalBytes += n
		// The useful data line is released before its blank-line delimiter is
		// read, so do not inject a keepalive in the middle of that SSE event.
		if err == nil {
			eventBoundary = false
		}
		initialBuffer.Reset()
		return err
	}

	var stopFirstUsefulContentTimer func()
	if options.firstUsefulContentTimeout > 0 {
		timer := time.AfterFunc(options.firstUsefulContentTimeout, func() {
			if preflightReleased.Load() {
				return
			}
			firstUsefulContentTimedOut.Store(true)
			// Closing the upstream body unblocks a pending ReadBytes call, so this
			// attempt can be retried before it emits any useful content.
			_ = raw.Body.Close()
		})
		stopFirstUsefulContentTimer = func() {
			timer.Stop()
		}
		defer stopFirstUsefulContentTimer()
	}

	writeStreamingLineLocked := func(line []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		n, err := writeStreamingLine(w, line, requestLog, hooks...)
		totalBytes += n
		if err == nil {
			eventBoundary = len(bytes.TrimSpace(line)) == 0
		}
		return err
	}

	if !options.deferInitialKeepAlive {
		if err := func() error {
			writeMu.Lock()
			defer writeMu.Unlock()
			return sendKeepAliveLocked()
		}(); err != nil {
			return totalBytes, clientStarted, err
		}
	}

	stopKeepAlive := make(chan struct{})
	keepAliveStopped := make(chan struct{})
	keepAliveInterval := options.keepAliveInterval
	if keepAliveInterval <= 0 {
		keepAliveInterval = codexStreamGuardKeepAliveInterval
	}
	go func() {
		defer close(keepAliveStopped)
		ticker := time.NewTicker(keepAliveInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				writeMu.Lock()
				err := sendKeepAliveLocked()
				writeMu.Unlock()
				if err != nil {
					fmt.Printf("[WARN] Codex SSE 保活写入失败: %v\n", err)
					return
				}
			case <-stopKeepAlive:
				return
			}
		}
	}()
	defer func() {
		close(stopKeepAlive)
		<-keepAliveStopped
	}()

	reader := bufio.NewReader(raw.Body)
	for {
		line, err := reader.ReadBytes('\n')
		if firstUsefulContentTimedOut.Load() && !preflightReleased.Load() {
			return totalBytes, clientStarted, errCodexFirstTextTimeout
		}
		if len(line) > 0 {
			state.observeLine(line)
			if state.sawCompleted || state.sawFailed || state.sawIncomplete {
				terminalEventSeen.Store(true)
			}
			if !completionCommitted && state.completedSuccessfully() && options.onSuccessfulCompleted != nil {
				// response.completed is the protocol's terminal success event. Commit
				// its alias immediately so a continuation can arrive while the
				// upstream keeps the SSE connection open after completion.
				options.onSuccessfulCompleted(state.responseID)
				completionCommitted = true
			}
			if released {
				if writeErr := writeStreamingLineLocked(line); writeErr != nil {
					return totalBytes, clientStarted, writeErr
				}
				if (state.sawFailed || state.sawIncomplete) && len(bytes.TrimSpace(line)) == 0 {
					return totalBytes, clientStarted, errCodexTerminalStreamFailure
				}
			} else {
				initialBuffer.Write(line)
				if !state.sawUsefulContent {
					switch {
					case state.sawFailed || state.sawIncomplete:
						return totalBytes, clientStarted, errCodexTerminalStreamFailure
					case state.sawCompleted:
						// A syntactically completed response with no text, reasoning or
						// tool output is still unusable to the caller.
						return totalBytes, clientStarted, errCodexEmptyStream
					case initialBuffer.Len() >= codexStreamGuardMaxInitialBufferBytes && options.firstUsefulContentTimeout > 0:
						return totalBytes, clientStarted, errCodexFirstTextTimeout
					case initialBuffer.Len() >= codexStreamGuardMaxInitialBufferBytes:
						return totalBytes, clientStarted, errCodexInitialBufferLimit
					}
					continue
				}
				if stopFirstUsefulContentTimer != nil {
					stopFirstUsefulContentTimer()
				}
				if writeErr := flushInitialBuffer(); writeErr != nil {
					return totalBytes, clientStarted, writeErr
				}
			}
		}

		if err != nil {
			if firstUsefulContentTimedOut.Load() && !preflightReleased.Load() {
				return totalBytes, clientStarted, errCodexFirstTextTimeout
			}
			if !released {
				if err == io.EOF && (state.sawFailed || state.sawIncomplete) {
					return totalBytes, clientStarted, errCodexTerminalStreamFailure
				}
				if err == io.EOF {
					return totalBytes, clientStarted, errCodexEmptyStream
				}
				return totalBytes, clientStarted, fmt.Errorf("error streaming response before useful content: %w", err)
			}
			if state.sawFailed || state.sawIncomplete {
				return totalBytes, clientStarted, errCodexTerminalStreamFailure
			}
			if !state.sawCompleted {
				// An abrupt HTTP/1.1 chunked-stream close can be surfaced as either
				// io.EOF or io.ErrUnexpectedEOF. In both cases the required terminal
				// response.completed event was never delivered.
				return totalBytes, clientStarted, errCodexMissingCompletion
			}
			// response.completed establishes a successful Responses result. A late
			// transport close after that terminal event is harmless.
			return totalBytes, clientStarted, nil
		}
	}
}

func responseWriterWritten(w http.ResponseWriter) bool {
	type writtenChecker interface {
		Written() bool
	}
	if checker, ok := w.(writtenChecker); ok {
		return checker.Written()
	}
	return false
}

func writeStreamingBuffer(w http.ResponseWriter, data []byte, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	reader := bufio.NewReader(bytes.NewReader(data))
	totalBytes := int64(0)
	for {
		line, err := reader.ReadBytes('\n')
		if len(line) > 0 {
			n, writeErr := writeStreamingLine(w, line, requestLog, hooks...)
			totalBytes += n
			if writeErr != nil {
				return totalBytes, writeErr
			}
		}
		if err != nil {
			if err == io.EOF {
				return totalBytes, nil
			}
			return totalBytes, err
		}
	}
}

func writeStreamingLine(w http.ResponseWriter, line []byte, requestLog *ReqeustLog, hooks ...xrequest.ResponseHook) (int64, error) {
	originalLine := make([]byte, len(line))
	copy(originalLine, line)

	trimmedLine := bytes.TrimRight(line, "\n")
	outputLine := originalLine
	if len(bytes.TrimSpace(trimmedLine)) > 0 {
		if requestLog != nil {
			requestLog.markFirstEvent()
		}
		flush := true
		processedLine := trimmedLine
		for _, hook := range hooks {
			flush, processedLine = hook(processedLine)
		}
		if !flush {
			return 0, nil
		}
		if bytes.HasSuffix(originalLine, []byte("\n")) {
			processedLine = append(processedLine, '\n')
		}
		outputLine = processedLine
	}
	if requestLog != nil && defaultActiveRequestTracker.IsRetryRequested(requestLog.ActiveRequestID) {
		requestLog.markRetryRequested()
		return 0, errActiveRequestRetryRequested
	}

	n, err := w.Write(outputLine)
	if err != nil {
		return int64(n), fmt.Errorf("error writing streaming response: %w", err)
	}
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	return int64(n), nil
}

func copyStreamingResponseHeaders(dst, src http.Header) {
	for key, values := range src {
		if isHopByHopHeader(key, src) || strings.EqualFold(key, "content-length") || strings.EqualFold(key, "content-encoding") {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
	dst.Set("X-Accel-Buffering", "no")
	dst.Set("Cache-Control", appendCacheControlDirective(dst.Get("Cache-Control"), "no-cache"))
}

func normalizeStreamingResponseHeaders(header http.Header) {
	header.Set("Content-Type", "text/event-stream; charset=utf-8")
	header.Set("Cache-Control", appendCacheControlDirective(header.Get("Cache-Control"), "no-transform"))
	header.Del("Content-Encoding")
	header.Del("Content-Length")
}

func appendCacheControlDirective(value, directive string) string {
	directive = strings.TrimSpace(directive)
	if directive == "" {
		return value
	}
	if strings.TrimSpace(value) == "" {
		return directive
	}
	for _, part := range strings.Split(value, ",") {
		if strings.EqualFold(strings.TrimSpace(part), directive) {
			return value
		}
	}
	return value + ", " + directive
}

func writeOpenAIChatJSONResponse(w http.ResponseWriter, resp *xrequest.Response, requestLog *ReqeustLog) error {
	if resp == nil || resp.RawResponse == nil {
		return fmt.Errorf("empty upstream response")
	}

	if resp.RawResponse.Body == nil {
		return fmt.Errorf("empty upstream response body")
	}
	defer resp.RawResponse.Body.Close()
	body, err := io.ReadAll(resp.RawResponse.Body)
	if err != nil {
		return err
	}
	OpenAIChatParseTokenUsageFromResponse(string(body), requestLog)

	for key, values := range resp.Headers() {
		if isHopByHopHeader(key, resp.Headers()) || strings.EqualFold(key, "content-length") || strings.EqualFold(key, "content-encoding") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	if w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Del("Content-Length")
	status := resp.StatusCode()
	if status == 0 {
		status = http.StatusOK
	}
	if requestLog != nil {
		defaultActiveRequestTracker.MarkResponseStarted(requestLog.ActiveRequestID)
	}
	w.WriteHeader(status)

	_, err = w.Write(body)
	return err
}

// extractUpstreamError 从供应商响应中提取原始错误信息（最多 512 字节）
func extractUpstreamError(resp *xrequest.Response) (string, error) {
	if resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return "", nil
	}
	defer resp.RawResponse.Body.Close()
	type readResult struct {
		raw []byte
		err error
	}
	done := make(chan readResult, 1)
	go func() {
		raw, err := io.ReadAll(io.LimitReader(resp.RawResponse.Body, 513))
		done <- readResult{raw: raw, err: err}
	}()
	timer := time.NewTimer(500 * time.Millisecond)
	defer timer.Stop()
	var body string
	select {
	case read := <-done:
		if read.err != nil {
			return "", read.err
		}
		body = string(read.raw)
	case <-timer.C:
		// Closing the body interrupts the background read on net/http bodies.
		_ = resp.RawResponse.Body.Close()
		return "", errors.New("读取供应商错误响应超时")
	}
	if body == "" {
		return "", nil
	}
	// 截断过长的错误信息
	if len(body) > 512 {
		body = body[:512] + "..."
	}
	return body, nil
}

func cloneHeaders(header http.Header) http.Header {
	cloned := make(http.Header, len(header))
	for key, values := range header {
		cloned[key] = append([]string(nil), values...)
	}
	return cloned
}

func removeHopByHopHeaders(headers http.Header) {
	if headers == nil {
		return
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			deleteHeaderCaseInsensitive(headers, strings.TrimSpace(token))
		}
	}
	for _, key := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		deleteHeaderCaseInsensitive(headers, key)
	}
}

func isHopByHopHeader(key string, headers http.Header) bool {
	if strings.EqualFold(key, "Connection") {
		return true
	}
	for _, value := range headers.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(token), key) {
				return true
			}
		}
	}
	switch strings.ToLower(key) {
	case "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade":
		return true
	default:
		return false
	}
}

func deleteHeaderCaseInsensitive(headers any, target string) {
	switch typed := headers.(type) {
	case http.Header:
		for key := range typed {
			if strings.EqualFold(key, target) {
				delete(typed, key)
			}
		}
	case map[string]string:
		for key := range typed {
			if strings.EqualFold(key, target) {
				delete(typed, key)
			}
		}
	}
}

func removeInboundAuthHeaders(headers any) {
	deleteHeaderCaseInsensitive(headers, "authorization")
	deleteHeaderCaseInsensitive(headers, "x-api-key")
	deleteHeaderCaseInsensitive(headers, codexRelayKeyHeader)
}

func stripClientAddressHeadersForLocalRelay(headers http.Header, targetURL string) {
	if ClassifyNetworkScope(targetURL) != TrafficScopeLocal {
		return
	}

	// The outer request already records the real client address. Carrying proxy
	// identity headers into a localhost provider makes the nested relay treat the
	// loopback hop as a second public client request and double-count its body.
	for _, key := range []string{
		"Forwarded",
		"X-Forwarded-For",
		"X-Real-IP",
		"CF-Connecting-IP",
		"True-Client-IP",
	} {
		deleteHeaderCaseInsensitive(headers, key)
	}
}

func flattenQuery(values url.Values) url.Values {
	query := make(url.Values, len(values))
	for key, items := range values {
		query[key] = append([]string(nil), items...)
	}
	return query
}

func joinURL(base string, endpoint string) string {
	base = strings.TrimSuffix(base, "/")
	endpoint = "/" + strings.TrimPrefix(endpoint, "/")
	return base + endpoint
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func ensureRequestLogColumn(db *sql.DB, column string, definition string) error {
	query := fmt.Sprintf("SELECT COUNT(*) FROM pragma_table_info('request_log') WHERE name = '%s'", column)
	var count int
	if err := db.QueryRow(query).Scan(&count); err != nil {
		return err
	}
	if count == 0 {
		alter := fmt.Sprintf("ALTER TABLE request_log ADD COLUMN %s %s", column, definition)
		if _, err := db.Exec(alter); err != nil {
			return err
		}
	}
	return nil
}

func ensureRequestLogTable() error {
	db, err := xdb.DB("default")
	if err != nil {
		return err
	}
	return ensureRequestLogTableWithDB(db)
}

func ensureRequestLogTableWithDB(db *sql.DB) error {
	const createTableSQL = `CREATE TABLE IF NOT EXISTS request_log (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id TEXT,
		platform TEXT,
		model TEXT,
		provider TEXT,
		relay_key_id TEXT,
		http_code INTEGER,
		input_tokens INTEGER,
		output_tokens INTEGER,
		cache_create_tokens INTEGER,
		cache_read_tokens INTEGER,
		reasoning_tokens INTEGER,
		is_stream INTEGER DEFAULT 0,
		duration_sec REAL DEFAULT 0,
		upstream_header_sec REAL DEFAULT 0,
		first_event_sec REAL DEFAULT 0,
		first_text_sec REAL DEFAULT 0,
		error_message TEXT,
			exclude_from_total INTEGER DEFAULT 0,
			traffic_trace_id TEXT,
			client_network_scope TEXT,
			client_request_bytes INTEGER DEFAULT 0,
			client_response_bytes INTEGER DEFAULT 0,
			upstream_request_bytes INTEGER DEFAULT 0,
			upstream_response_bytes INTEGER DEFAULT 0,
			retry_request_bytes INTEGER DEFAULT 0,
			retry_response_bytes INTEGER DEFAULT 0,
			upstream_attempts INTEGER DEFAULT 0,
			public_ingress_bytes INTEGER DEFAULT 0,
			public_egress_bytes INTEGER DEFAULT 0,
			local_ingress_bytes INTEGER DEFAULT 0,
			local_egress_bytes INTEGER DEFAULT 0,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`

	if _, err := db.Exec(createTableSQL); err != nil {
		return err
	}

	if err := ensureRequestLogColumn(db, "created_at", "DATETIME DEFAULT CURRENT_TIMESTAMP"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "user_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "relay_key_id", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "is_stream", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "duration_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "first_token_duration_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "client_ip", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "upstream_header_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "first_event_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "first_text_sec", "REAL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "error_message", "TEXT"); err != nil {
		return err
	}
	if err := ensureRequestLogColumn(db, "exclude_from_total", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	trafficColumns := []struct {
		name       string
		definition string
	}{
		{"traffic_trace_id", "TEXT"},
		{"client_network_scope", "TEXT"},
		{"client_request_bytes", "INTEGER DEFAULT 0"},
		{"client_response_bytes", "INTEGER DEFAULT 0"},
		{"upstream_request_bytes", "INTEGER DEFAULT 0"},
		{"upstream_response_bytes", "INTEGER DEFAULT 0"},
		{"retry_request_bytes", "INTEGER DEFAULT 0"},
		{"retry_response_bytes", "INTEGER DEFAULT 0"},
		{"upstream_attempts", "INTEGER DEFAULT 0"},
		{"public_ingress_bytes", "INTEGER DEFAULT 0"},
		{"public_egress_bytes", "INTEGER DEFAULT 0"},
		{"local_ingress_bytes", "INTEGER DEFAULT 0"},
		{"local_egress_bytes", "INTEGER DEFAULT 0"},
	}
	for _, column := range trafficColumns {
		if err := ensureRequestLogColumn(db, column.name, column.definition); err != nil {
			return err
		}
	}

	return nil
}

type requestLogIndexDefinition struct {
	name      string
	createSQL string
}

var requestLogIndexDefinitions = []requestLogIndexDefinition{
	{
		name:      "idx_request_log_created_at",
		createSQL: "CREATE INDEX IF NOT EXISTS idx_request_log_created_at ON request_log(created_at)",
	},
	{
		name:      "idx_request_log_user_platform_created_at",
		createSQL: "CREATE INDEX IF NOT EXISTS idx_request_log_user_platform_created_at ON request_log(user_id, platform, created_at)",
	},
	{
		name:      "idx_request_log_user_created_at",
		createSQL: "CREATE INDEX IF NOT EXISTS idx_request_log_user_created_at ON request_log(user_id, created_at)",
	},
	{
		name:      "idx_request_log_user_id",
		createSQL: "CREATE INDEX IF NOT EXISTS idx_request_log_user_id ON request_log(user_id, id DESC)",
	},
	{
		name:      "idx_request_log_user_error_id",
		createSQL: "CREATE INDEX IF NOT EXISTS idx_request_log_user_error_id ON request_log(user_id, id DESC) WHERE http_code >= 400",
	},
}

func missingRequestLogIndexes(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_schema WHERE type = 'index' AND tbl_name = 'request_log'`)
	if err != nil {
		return nil, err
	}
	existing := make(map[string]struct{}, len(requestLogIndexDefinitions))
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return nil, err
		}
		existing[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	missing := make([]string, 0, len(requestLogIndexDefinitions))
	for _, index := range requestLogIndexDefinitions {
		if _, ok := existing[index.name]; !ok {
			missing = append(missing, index.name)
		}
	}
	return missing, nil
}

func createMissingRequestLogIndexes(db *sql.DB, beforeCreate func(string), afterCreate func(string)) error {
	missing, err := missingRequestLogIndexes(db)
	if err != nil {
		return fmt.Errorf("list request_log indexes: %w", err)
	}
	missingSet := make(map[string]struct{}, len(missing))
	for _, name := range missing {
		missingSet[name] = struct{}{}
	}

	for _, index := range requestLogIndexDefinitions {
		if _, ok := missingSet[index.name]; !ok {
			continue
		}
		if beforeCreate != nil {
			beforeCreate(index.name)
		}
		if _, err := db.Exec(index.createSQL); err != nil {
			return fmt.Errorf("create request_log index %s: %w", index.name, err)
		}
		if afterCreate != nil {
			afterCreate(index.name)
		}
	}
	return nil
}

func ensureRequestLogIndexes(db *sql.DB) error {
	return createMissingRequestLogIndexes(db, nil, nil)
}

func ReqeustLogHook(c *gin.Context, kind string, usage *ReqeustLog) func(data []byte) (bool, []byte) { // SSE 钩子：累计字节和解析 token 用量
	return func(data []byte) (bool, []byte) {
		payload := strings.TrimSpace(string(data))

		parserFn := ClaudeCodeParseTokenUsageFromResponse
		switch kind {
		case "codex", "openai-responses":
			parserFn = CodexParseTokenUsageFromResponse
		case "openai-chat":
			parserFn = OpenAIChatParseTokenUsageFromResponse
		}
		parseEventPayload(payload, parserFn, usage)
		markFirstTextFromSSEPayload(payload, usage)
		usage.syncActiveRequest()

		return true, data
	}
}

func parseEventPayload(payload string, parser func(string, *ReqeustLog), usage *ReqeustLog) {
	lines := strings.Split(payload, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "data:") {
			parser(strings.TrimPrefix(line, "data: "), usage)
		}
	}
}

func markFirstTextFromSSEPayload(payload string, usage *ReqeustLog) {
	if usage == nil || usage.FirstTextSec > 0 {
		return
	}
	lines := strings.Split(payload, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" || data == "[DONE]" || !json.Valid([]byte(data)) {
			continue
		}
		if ssePayloadHasText(data) {
			usage.markFirstText()
			return
		}
	}
}

func ssePayloadHasText(data string) bool {
	responsesState := codexStreamGuardState{}
	responsesState.observeLine([]byte("data: " + data))
	if responsesState.sawUsefulContent {
		return true
	}

	eventType := gjson.Get(data, "type").String()
	switch eventType {
	case "response.output_text.delta", "response.function_call_arguments.delta":
		return strings.TrimSpace(gjson.Get(data, "delta").String()) != ""
	}

	textPaths := []string{
		"delta.text",
		"content_block.text",
		"content.0.text",
		"choices.0.delta.content",
		"choices.0.message.content",
	}
	for _, path := range textPaths {
		if gjson.Get(data, path).String() != "" {
			return true
		}
	}

	content := gjson.Get(data, "content")
	if content.IsArray() {
		for _, item := range content.Array() {
			if item.Get("text").String() != "" {
				return true
			}
		}
	}
	return false
}

type ReqeustLog struct {
	ID                          int64   `json:"id"`
	UserID                      string  `json:"user_id"`
	Platform                    string  `json:"platform"` // claude、openai-responses 或 openai-chat
	Model                       string  `json:"model"`
	Provider                    string  `json:"provider"` // provider name
	RelayKeyID                  string  `json:"relay_key_id"`
	RelayKeyName                string  `json:"relay_key_name"`
	HttpCode                    int     `json:"http_code"`
	InputTokens                 int     `json:"input_tokens"`
	OutputTokens                int     `json:"output_tokens"`
	CacheCreateTokens           int     `json:"cache_create_tokens"`
	CacheReadTokens             int     `json:"cache_read_tokens"`
	ReasoningTokens             int     `json:"reasoning_tokens"`
	ExcludeFromTotalTraffic     bool    `json:"exclude_from_total"`
	IsStream                    bool    `json:"is_stream"`
	DurationSec                 float64 `json:"duration_sec"`
	FirstTokenDurationSec       float64 `json:"first_token_duration_sec"`
	ClientIP                    string  `json:"client_ip"`
	UpstreamHeaderSec           float64 `json:"upstream_header_sec"`
	FirstEventSec               float64 `json:"first_event_sec"`
	FirstTextSec                float64 `json:"first_text_sec"`
	ErrorMessage                string  `json:"error_message"`
	CreatedAt                   string  `json:"created_at"`
	Status                      string  `json:"status,omitempty"`
	RetryRequested              bool    `json:"retry_requested,omitempty"`
	TrafficTraceID              string  `json:"traffic_trace_id,omitempty"`
	ClientNetworkScope          string  `json:"client_network_scope,omitempty"`
	ClientRequestBytes          int64   `json:"client_request_bytes"`
	ClientResponseBytes         int64   `json:"client_response_bytes"`
	UpstreamRequestBytes        int64   `json:"upstream_request_bytes"`
	UpstreamResponseBytes       int64   `json:"upstream_response_bytes"`
	RetryRequestBytes           int64   `json:"retry_request_bytes"`
	RetryResponseBytes          int64   `json:"retry_response_bytes"`
	UpstreamAttempts            int     `json:"upstream_attempts"`
	PublicIngressBytes          int64   `json:"public_ingress_bytes"`
	PublicEgressBytes           int64   `json:"public_egress_bytes"`
	LocalIngressBytes           int64   `json:"local_ingress_bytes"`
	LocalEgressBytes            int64   `json:"local_egress_bytes"`
	QueuePosition               int     `json:"queue_position,omitempty"`
	QueueStartedAt              string  `json:"queue_started_at,omitempty"`
	ActiveRequestID             int64   `json:"-"`
	QueueKey                    string  `json:"-"`
	startedAt                   time.Time
	inputTokensIncludeCacheRead bool
	attemptPersisted            bool
	traffic                     *requestTrafficState
}

func (r *ReqeustLog) elapsedSinceStart() float64 {
	if r == nil || r.startedAt.IsZero() {
		return 0
	}
	return time.Since(r.startedAt).Seconds()
}

func (r *ReqeustLog) markUpstreamHeaders() {
	if r != nil && r.UpstreamHeaderSec == 0 {
		r.UpstreamHeaderSec = r.elapsedSinceStart()
	}
}

func (r *ReqeustLog) markRetryRequested() {
	if r == nil {
		return
	}
	r.RetryRequested = true
	r.Status = requestLogStatusRetrying
	r.HttpCode = 499
	r.ErrorMessage = "重试"
	r.InputTokens = 0
	r.OutputTokens = 0
	r.CacheCreateTokens = 0
	r.CacheReadTokens = 0
	r.ReasoningTokens = 0
	r.FirstTokenDurationSec = 0
	r.FirstEventSec = 0
	r.FirstTextSec = 0
	r.syncActiveRequest()
}

// isEmptyShell returns true if the response is an empty shell: all token counts are zero.
func (r *ReqeustLog) isEmptyShell() bool {
	if r == nil {
		return false
	}
	return r.InputTokens == 0 && r.OutputTokens == 0 && r.CacheReadTokens == 0 && r.CacheCreateTokens == 0 && r.ReasoningTokens == 0
}

// readResponseBody reads the full response body from a non-streaming response.
// Closes the underlying body after reading.
func readResponseBody(resp *xrequest.Response) ([]byte, error) {
	if resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return nil, fmt.Errorf("empty response")
	}
	defer resp.RawResponse.Body.Close()
	data, err := io.ReadAll(resp.RawResponse.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

// readResponseBodyWithFirstTextTimeout treats a delayed non-streaming response
// body as a first-text timeout too. This also covers upstreams that return SSE
// despite the client omitting the optional stream field.
func readResponseBodyWithFirstTextTimeout(resp *xrequest.Response, timeout time.Duration) ([]byte, error) {
	if timeout <= 0 || resp == nil || resp.RawResponse == nil || resp.RawResponse.Body == nil {
		return readResponseBody(resp)
	}

	var timedOut atomic.Bool
	timer := time.AfterFunc(timeout, func() {
		timedOut.Store(true)
		_ = resp.RawResponse.Body.Close()
	})
	body, err := readResponseBody(resp)
	if !timer.Stop() && timedOut.Load() {
		return nil, errCodexFirstTextTimeout
	}
	if timedOut.Load() {
		return nil, errCodexFirstTextTimeout
	}
	return body, err
}

// copyResponseHeaders copies upstream response headers to the client writer,
// filtering out hop-by-hop and content-length headers.
func copyResponseHeaders(w http.ResponseWriter, upstream http.Header) {
	for key, values := range upstream {
		if isHopByHopHeader(key, upstream) || strings.EqualFold(key, "content-length") || strings.EqualFold(key, "content-encoding") {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
}

// parseNonStreamingTokens extracts token usage from a non-streaming response body
// and populates requestLog fields.
func parseNonStreamingTokens(body []byte, kind string, requestLog *ReqeustLog) {
	if requestLog == nil || len(body) == 0 {
		return
	}
	result := gjson.ParseBytes(body)

	// Try common usage paths
	usage := result.Get("usage")
	if usage.Exists() {
		requestLog.InputTokens = int(usage.Get("input_tokens").Int())
		requestLog.OutputTokens = int(usage.Get("output_tokens").Int())
		if ct := usage.Get("cache_read_input_tokens"); ct.Exists() {
			requestLog.CacheReadTokens = int(ct.Int())
		}
		if ct := usage.Get("cache_creation_input_tokens"); ct.Exists() {
			requestLog.CacheCreateTokens = int(ct.Int())
		}
		if rt := usage.Get("reasoning_tokens"); rt.Exists() {
			requestLog.ReasoningTokens = int(rt.Int())
		}
		return
	}

	// Anthropic Messages API format
	if result.Get("type").String() == "message" {
		requestLog.InputTokens = int(result.Get("usage.input_tokens").Int())
		requestLog.OutputTokens = int(result.Get("usage.output_tokens").Int())
		if ct := result.Get("usage.cache_read_input_tokens"); ct.Exists() {
			requestLog.CacheReadTokens = int(ct.Int())
		}
		return
	}
}

// hasContentInResponse checks whether a non-streaming response body contains actual
// text content, tool calls, or reasoning output — beyond just empty JSON structures.
func hasContentInResponse(body []byte, kind string) bool {
	if len(body) == 0 {
		return false
	}
	result := gjson.ParseBytes(body)

	// Anthropic Messages format
	if result.Get("type").String() == "message" {
		content := result.Get("content")
		if content.IsArray() && len(content.Array()) > 0 {
			for _, block := range content.Array() {
				t := block.Get("type").String()
				switch t {
				case "text":
					if strings.TrimSpace(block.Get("text").String()) != "" {
						return true
					}
				case "tool_use":
					return true
				}
			}
		}
		return false
	}

	// OpenAI Chat Completions format
	choices := result.Get("choices")
	if choices.IsArray() && len(choices.Array()) > 0 {
		for _, choice := range choices.Array() {
			msg := choice.Get("message")
			if strings.TrimSpace(msg.Get("content").String()) != "" {
				return true
			}
			if strings.TrimSpace(msg.Get("reasoning_content").String()) != "" {
				return true
			}
			if msg.Get("tool_calls").Exists() && len(msg.Get("tool_calls").Array()) > 0 {
				return true
			}
		}
		return false
	}

	// OpenAI Responses format
	output := result.Get("output")
	if output.IsArray() {
		return responsesOutputHasUsefulContent(output)
	}

	// Unknown format: treat as having content (conservative)
	return true
}

func (r *ReqeustLog) markFirstEvent() {
	if r != nil {
		changed := false
		if r.FirstEventSec == 0 {
			r.FirstEventSec = r.elapsedSinceStart()
			changed = true
		}
		if changed {
			r.syncActiveRequest()
		}
	}
}

func (r *ReqeustLog) markFirstText() {
	if r != nil {
		changed := false
		if r.FirstTextSec == 0 {
			r.FirstTextSec = r.elapsedSinceStart()
			changed = true
		}
		if r.FirstTokenDurationSec == 0 {
			r.FirstTokenDurationSec = r.elapsedSinceStart()
			changed = true
		}
		if changed {
			r.syncActiveRequest()
		}
	}
}

func (r *ReqeustLog) syncActiveRequest() {
	if r == nil || r.ActiveRequestID == 0 {
		return
	}
	defaultActiveRequestTracker.Update(r.ActiveRequestID, r)
}

// claude code usage parser
func ClaudeCodeParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	usage.InputTokens += int(gjson.Get(data, "message.usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "message.usage.output_tokens").Int())
	usage.CacheCreateTokens += int(gjson.Get(data, "message.usage.cache_creation_input_tokens").Int())
	usage.CacheReadTokens += int(gjson.Get(data, "message.usage.cache_read_input_tokens").Int())

	usage.InputTokens += int(gjson.Get(data, "usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "usage.output_tokens").Int())
	usage.CacheCreateTokens += int(gjson.Get(data, "usage.cache_creation_input_tokens").Int())
	cacheReadTokens := gjson.Get(data, "usage.cache_read_input_tokens").Int()
	if cacheReadTokens == 0 {
		cacheReadTokens = gjson.Get(data, "usage.input_tokens_details.cached_tokens").Int()
		if cacheReadTokens > 0 {
			usage.inputTokensIncludeCacheRead = true
		}
	}
	usage.CacheReadTokens += int(cacheReadTokens)
	usage.ReasoningTokens += int(gjson.Get(data, "usage.output_tokens_details.reasoning_tokens").Int())
}

// codex usage parser
func CodexParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	usage.InputTokens += int(gjson.Get(data, "response.usage.input_tokens").Int())
	usage.OutputTokens += int(gjson.Get(data, "response.usage.output_tokens").Int())
	usage.CacheReadTokens += int(gjson.Get(data, "response.usage.input_tokens_details.cached_tokens").Int())
	if usage.CacheReadTokens > 0 {
		usage.inputTokensIncludeCacheRead = true
	}
	usage.ReasoningTokens += int(gjson.Get(data, "response.usage.output_tokens_details.reasoning_tokens").Int())
}

func OpenAIChatParseTokenUsageFromResponse(data string, usage *ReqeustLog) {
	if usage == nil {
		return
	}
	usageResult := gjson.Get(data, "usage")
	if !usageResult.Exists() {
		return
	}

	usage.InputTokens += int(usageResult.Get("prompt_tokens").Int())
	usage.OutputTokens += int(usageResult.Get("completion_tokens").Int())
	cacheReadTokens := usageResult.Get("prompt_tokens_details.cached_tokens").Int()
	usage.CacheReadTokens += int(cacheReadTokens)
	if cacheReadTokens > 0 {
		usage.inputTokensIncludeCacheRead = true
	}
	usage.ReasoningTokens += int(usageResult.Get("completion_tokens_details.reasoning_tokens").Int())
}

func ensureOpenAIChatStreamUsage(bodyBytes []byte) []byte {
	if !json.Valid(bodyBytes) {
		return bodyBytes
	}
	if gjson.GetBytes(bodyBytes, "stream_options.include_usage").Bool() {
		return bodyBytes
	}
	updated, err := sjson.SetBytes(bodyBytes, "stream_options.include_usage", true)
	if err != nil {
		return bodyBytes
	}
	return updated
}

// ReplaceModelInRequestBody 替换请求体中的模型名
// 使用 gjson + sjson 实现高性能 JSON 操作，避免完整反序列化
func ReplaceModelInRequestBody(bodyBytes []byte, newModel string) ([]byte, error) {
	// 检查请求体中是否存在 model 字段
	result := gjson.GetBytes(bodyBytes, "model")
	if !result.Exists() {
		return bodyBytes, fmt.Errorf("请求体中未找到 model 字段")
	}

	// 使用 sjson.SetBytes 替换模型名（高性能操作）
	modified, err := sjson.SetBytes(bodyBytes, "model", newModel)
	if err != nil {
		return bodyBytes, fmt.Errorf("替换模型名失败: %w", err)
	}

	return modified, nil
}

type modelsProviderResponse struct {
	statusCode  int
	header      http.Header
	contentType string
	body        []byte
}

type modelsListEntry struct {
	id   string
	body json.RawMessage
}

type modelsListEnvelope struct {
	Object string            `json:"object"`
	Data   []json.RawMessage `json:"data"`
}

type modelsFetchResult struct {
	provider Provider
	response *modelsProviderResponse
	entries  []modelsListEntry
	err      error
}

func parseModelsList(body []byte) ([]modelsListEntry, error) {
	var envelope struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("invalid models response JSON: %w", err)
	}
	if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
		return nil, errors.New("models response is missing data array")
	}

	var rawEntries []json.RawMessage
	if err := json.Unmarshal(envelope.Data, &rawEntries); err != nil {
		return nil, fmt.Errorf("models response data is not an array: %w", err)
	}
	entries := make([]modelsListEntry, 0, len(rawEntries))
	for _, rawEntry := range rawEntries {
		var model struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(rawEntry, &model); err != nil {
			return nil, fmt.Errorf("invalid model entry: %w", err)
		}
		model.ID = strings.TrimSpace(model.ID)
		if model.ID == "" {
			return nil, errors.New("model entry is missing id")
		}
		entries = append(entries, modelsListEntry{
			id:   model.ID,
			body: append(json.RawMessage(nil), rawEntry...),
		})
	}
	return entries, nil
}

func reverseMappedModelAliases(provider Provider, upstreamModel string) []string {
	if len(provider.ModelMapping) == 0 {
		return nil
	}

	externalModels := make([]string, 0, len(provider.ModelMapping))
	for externalModel := range provider.ModelMapping {
		externalModels = append(externalModels, externalModel)
	}
	sort.Strings(externalModels)

	aliases := make([]string, 0)
	seen := make(map[string]struct{})
	for _, externalPattern := range externalModels {
		internalPattern := strings.TrimSpace(provider.ModelMapping[externalPattern])
		externalPattern = strings.TrimSpace(externalPattern)
		if externalPattern == "" || internalPattern == "" {
			continue
		}

		alias := ""
		switch {
		case !strings.Contains(externalPattern, "*") && internalPattern == upstreamModel:
			alias = externalPattern
		case strings.Count(externalPattern, "*") == 1 &&
			strings.Count(internalPattern, "*") == 1 &&
			matchWildcard(internalPattern, upstreamModel):
			alias = applyWildcardMapping(internalPattern, externalPattern, upstreamModel)
		}
		alias = strings.TrimSpace(alias)
		if alias == "" || strings.Contains(alias, "*") {
			continue
		}
		if _, ok := seen[alias]; ok {
			continue
		}
		seen[alias] = struct{}{}
		aliases = append(aliases, alias)
	}
	return aliases
}

func mapModelsListForProvider(entries []modelsListEntry, provider Provider) ([]modelsListEntry, error) {
	mapped := make([]modelsListEntry, 0, len(entries))
	seen := make(map[string]struct{}, len(entries))
	add := func(entry modelsListEntry, modelID string) error {
		modelID = strings.TrimSpace(modelID)
		if modelID == "" {
			return nil
		}
		if _, ok := seen[modelID]; ok {
			return nil
		}
		body := entry.body
		if modelID != entry.id {
			updated, err := sjson.SetBytes(body, "id", modelID)
			if err != nil {
				return fmt.Errorf("failed to expose mapped model %q: %w", modelID, err)
			}
			body = updated
		}
		seen[modelID] = struct{}{}
		mapped = append(mapped, modelsListEntry{id: modelID, body: body})
		return nil
	}

	for _, entry := range entries {
		aliases := reverseMappedModelAliases(provider, entry.id)
		if len(aliases) == 0 {
			if err := add(entry, entry.id); err != nil {
				return nil, err
			}
			continue
		}
		for _, alias := range aliases {
			if err := add(entry, alias); err != nil {
				return nil, err
			}
		}
	}
	return mapped, nil
}

func marshalModelsList(entries []modelsListEntry) ([]byte, error) {
	data := make([]json.RawMessage, 0, len(entries))
	for _, entry := range entries {
		data = append(data, entry.body)
	}
	return json.Marshal(modelsListEnvelope{Object: "list", Data: data})
}

func mergeModelsFetchResults(results []modelsFetchResult) []modelsListEntry {
	merged := make([]modelsListEntry, 0)
	seen := make(map[string]struct{})
	for _, result := range results {
		for _, entry := range result.entries {
			if _, ok := seen[entry.id]; ok {
				continue
			}
			seen[entry.id] = struct{}{}
			merged = append(merged, entry)
		}
	}
	return merged
}

func applyModelsMappingToResponse(response *modelsProviderResponse, provider Provider) error {
	if response == nil || len(provider.ModelMapping) == 0 {
		return nil
	}
	entries, err := parseModelsList(response.body)
	if err != nil {
		return err
	}
	entries, err = mapModelsListForProvider(entries, provider)
	if err != nil {
		return err
	}
	body, err := marshalModelsList(entries)
	if err != nil {
		return fmt.Errorf("failed to encode mapped models response: %w", err)
	}
	response.body = body
	response.contentType = "application/json"
	response.header.Del("Content-Length")
	response.header.Set("Content-Type", response.contentType)
	return nil
}

func sanitizeModelsFailure(
	response *modelsProviderResponse,
	fetchErr error,
	provider Provider,
) (*modelsProviderResponse, error) {
	if response != nil {
		redactedBody := redactProviderSecret(string(response.body), provider)
		if redactedBody != string(response.body) {
			response.body = []byte(redactedBody)
			response.header.Del("Content-Length")
		}
		for headerName, values := range response.header {
			for valueIndex, value := range values {
				values[valueIndex] = redactProviderSecret(value, provider)
			}
			response.header[headerName] = values
		}
		if fetchErr == nil {
			bodySummary := summarizeBodyForError(redactedBody, 1000)
			fetchErr = fmt.Errorf("upstream status %d: %s", response.statusCode, bodySummary)
		}
	}
	if fetchErr == nil {
		fetchErr = errors.New("empty models response")
	}
	redactedFetchError := redactProviderSecret(fetchErr.Error(), provider)
	if redactedFetchError != fetchErr.Error() {
		fetchErr = errors.New(redactedFetchError)
	}
	return response, fetchErr
}

func modelsPlatformCandidates(c *gin.Context, preferredKind string) []string {
	seen := make(map[string]bool)
	candidates := make([]string, 0, 3)
	add := func(kind string) {
		kind = providerPlatformForPool(kind)
		if strings.TrimSpace(kind) == "" || seen[kind] {
			return
		}
		seen[kind] = true
		candidates = append(candidates, kind)
	}

	add(preferredKind)
	bindings := relayKeyPoolBindingsFromContext(c)
	for _, kind := range []string{"openai-responses", "openai-chat", "claude"} {
		if _, ok := bindings[kind]; ok {
			add(kind)
		}
	}
	return candidates
}

func providersFromAttemptPlan(plan *providerAttemptPlan) []Provider {
	if plan == nil {
		return nil
	}
	providers := make([]Provider, 0, len(plan.active))
	seen := make(map[int64]bool, len(plan.active))
	for _, level := range plan.levels {
		for _, provider := range plan.levelGroups[level] {
			if provider.ID == 0 || seen[provider.ID] {
				continue
			}
			seen[provider.ID] = true
			providers = append(providers, provider)
		}
	}
	return providers
}

func providerIDsFromProviders(providers []Provider) []int64 {
	if len(providers) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(providers))
	seen := make(map[int64]bool, len(providers))
	for _, provider := range providers {
		if provider.ID == 0 || seen[provider.ID] {
			continue
		}
		seen[provider.ID] = true
		ids = append(ids, provider.ID)
	}
	return ids
}

func writeModelsProviderResponse(c *gin.Context, response *modelsProviderResponse) {
	if response == nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "empty models response"})
		return
	}
	for key, values := range response.header {
		if isHopByHopHeader(key, response.header) || strings.EqualFold(key, "Content-Length") {
			continue
		}
		for _, value := range values {
			c.Writer.Header().Add(key, value)
		}
	}
	c.Data(response.statusCode, response.contentType, response.body)
}

func (prs *ProviderRelayService) fetchModelsFromProvider(
	ctx context.Context,
	inboundHeaders http.Header,
	rawQuery string,
	provider Provider,
	logPrefix string,
) (*modelsProviderResponse, error) {
	endpoint := strings.TrimSpace(provider.ModelsEndpoint)
	if endpoint == "" {
		endpoint = "/v1/models"
	}
	targetURL := joinURL(provider.APIURL, endpoint)
	targetURL = appendRawQuery(targetURL, rawQuery)

	headers := cloneHeaders(inboundHeaders)
	removeInboundAuthHeaders(headers)
	removeHopByHopHeaders(headers)
	deleteHeaderCaseInsensitive(headers, "Accept-Encoding")

	authType := strings.ToLower(strings.TrimSpace(provider.ConnectivityAuthType))
	switch authType {
	case "x-api-key":
		headers.Set("x-api-key", provider.APIKey)
		headers.Set("anthropic-version", "2023-06-01")
	case "", "bearer":
		headers.Set("Authorization", fmt.Sprintf("Bearer %s", provider.APIKey))
	default:
		headerName := strings.TrimSpace(provider.ConnectivityAuthType)
		if headerName == "" || strings.EqualFold(headerName, "custom") {
			headerName = "Authorization"
		}
		headers.Set(headerName, provider.APIKey)
	}

	if headers.Get("Accept") == "" {
		headers.Set("Accept", "application/json")
	}
	headers.Set("Accept-Encoding", "identity")

	var (
		resp *http.Response
		err  error
	)
	for attempt := 0; attempt < 2; attempt++ {
		req, requestErr := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
		if requestErr != nil {
			return nil, fmt.Errorf("failed to create request: %w", requestErr)
		}
		req.Header = cloneHeaders(headers)
		client, _, clientErr := prs.requestClient(ctx)
		if clientErr != nil {
			if proxyErr, ok := isProxyRequestError(clientErr); ok {
				prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
			}
			if attempt == 0 {
				continue
			}
			return nil, clientErr
		}
		resp, err = client.Do(req)
		if err == nil {
			break
		}
		if proxyErr, ok := isProxyRequestError(err); ok {
			prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
			if attempt == 0 {
				continue
			}
		}
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %v", errClientAbort, err)
		}
		fmt.Printf("[%s] ✗ 请求失败: %s | 错误: %v\n", logPrefix, provider.Name, err)
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp == nil {
		return nil, errors.New("request failed without a response")
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if ctx.Err() != nil || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %v", errClientAbort, err)
		}
		fmt.Printf("[%s] ✗ 读取响应失败: %s | 错误: %v\n", logPrefix, provider.Name, err)
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return &modelsProviderResponse{
		statusCode:  resp.StatusCode,
		header:      resp.Header.Clone(),
		contentType: resp.Header.Get("Content-Type"),
		body:        body,
	}, nil
}

func (prs *ProviderRelayService) fetchManagedModelsFromProviders(
	c *gin.Context,
	providers []Provider,
	logPrefix string,
) []modelsFetchResult {
	results := make([]modelsFetchResult, len(providers))
	if len(providers) == 0 {
		return results
	}

	ctx := c.Request.Context()
	headers := cloneHeaders(c.Request.Header)
	rawQuery := c.Request.URL.RawQuery
	var wg sync.WaitGroup
	wg.Add(len(providers))
	for index, provider := range providers {
		index := index
		provider := provider
		go func() {
			defer wg.Done()
			result := modelsFetchResult{provider: provider}
			result.response, result.err = prs.fetchModelsFromProvider(ctx, headers, rawQuery, provider, logPrefix)
			if result.err == nil && result.response != nil &&
				result.response.statusCode >= http.StatusOK && result.response.statusCode < http.StatusMultipleChoices {
				entries, err := parseModelsList(result.response.body)
				if err == nil {
					entries, err = mapModelsListForProvider(entries, provider)
				}
				result.entries = entries
				result.err = err
			}
			results[index] = result
		}()
	}
	wg.Wait()
	return results
}

// forwardModelsRequest 共享的 /v1/models 请求转发逻辑。
// 模型列表请求也必须走 relay key 绑定的 pool，并过滤当前 pool 的拉黑状态。
func (prs *ProviderRelayService) forwardModelsRequest(
	c *gin.Context,
	kind string,
	logPrefix string,
) error {
	fmt.Printf("[%s] 收到 /v1/models 请求, kind=%s\n", logPrefix, kind)

	candidates := modelsPlatformCandidates(c, kind)
	if len(candidates) == 0 {
		c.JSON(http.StatusForbidden, gin.H{"error": "relay key 未绑定任何可用于 /v1/models 的供应商池"})
		return fmt.Errorf("relay key has no models pool binding")
	}

	var lastErr error
	var sawAllBlacklisted bool
	var sawPoolResolved bool
	var sawAccountPoolFailure bool
	var sawAccountPoolUnavailable bool
	var modelsStickyRequests []*accountPoolStickyRequest
	defer func() {
		for _, request := range modelsStickyRequests {
			prs.accountPoolStickyStore().abort(request)
		}
	}()

candidateLoop:
	for _, candidate := range candidates {
		var accountStickyRequest *accountPoolStickyRequest
		for {
			plan, poolResolved, selectErr := prs.buildProviderAttemptPlan(c, candidate, "")
			if selectErr != nil {
				lastErr = selectErr
				if poolResolved {
					sawPoolResolved = true
				}
				fmt.Printf("[%s][WARN] 跳过 %s 模型列表池: %v\n", logPrefix, candidate, selectErr)
				continue candidateLoop
			}
			sawPoolResolved = true
			accountPool := isAccountPool(plan.pool)
			if accountPool {
				if accountStickyRequest == nil {
					accountStickyRequest = prs.beginAccountPoolStickyRequest(c, plan, nil)
					if accountStickyRequest != nil {
						modelsStickyRequests = append(modelsStickyRequests, accountStickyRequest)
					}
				}
				prs.reorderAccountPoolAttemptPlan(plan, accountStickyRequest)
			}
			c.Request = c.Request.WithContext(withProviderPoolContext(c.Request.Context(), plan.pool, plan.userID))
			if len(plan.active) == 0 {
				if accountPool {
					sawAccountPoolUnavailable = true
				}
				if plan.allBlacklisted {
					sawAllBlacklisted = true
					lastErr = fmt.Errorf("池子 %s 内所有 provider 均在临时拉黑期", plan.pool.Name)
					fmt.Printf("[%s][WARN] %s\n", logPrefix, lastErr)
					continue candidateLoop
				}
				lastErr = fmt.Errorf("no providers available in pool %s/%s", candidate, plan.pool.Name)
				fmt.Printf("[%s][WARN] %s\n", logPrefix, lastErr)
				continue candidateLoop
			}

			providers := providersFromAttemptPlan(plan)
			if !accountPool && plan.pool.Mode == ProviderPoolModeManaged {
				results := prs.fetchManagedModelsFromProviders(c, providers, logPrefix)
				successCount := 0
				allFailuresBlacklisted := true
				var firstFailureResponse *modelsProviderResponse
				var firstFailureErr error
				var firstFailureWasProxy bool

				for index := range results {
					result := &results[index]
					if result.err == nil && result.response != nil &&
						result.response.statusCode >= http.StatusOK && result.response.statusCode < http.StatusMultipleChoices {
						successCount++
						fmt.Printf("[%s] ✓ 成功: %s | HTTP %d\n", logPrefix, result.provider.Name, result.response.statusCode)
						prs.recordProviderSuccessForUser(plan.userID, candidate, plan.poolID, result.provider)
						continue
					}

					if errors.Is(result.err, errClientAbort) || c.Request.Context().Err() != nil {
						return result.err
					}
					result.response, result.err = sanitizeModelsFailure(result.response, result.err, result.provider)
					fmt.Printf("[%s][WARN] Provider %s 模型列表失败: %v\n", logPrefix, result.provider.Name, result.err)
					_, proxyFailure := isProxyRequestError(result.err)
					blacklistedAfterFailure := false
					if !proxyFailure {
						blacklistedAfterFailure = prs.recordProviderFailureForUser(
							plan.userID, candidate, plan.poolID, plan.pool, result.provider, result.err.Error(),
						)
					}
					if !blacklistedAfterFailure {
						allFailuresBlacklisted = false
						if firstFailureErr == nil {
							firstFailureErr = result.err
							firstFailureWasProxy = proxyFailure
							if result.response != nil &&
								(result.response.statusCode < http.StatusOK || result.response.statusCode >= http.StatusMultipleChoices) {
								firstFailureResponse = result.response
							}
						}
					}
				}

				if c.Request.Context().Err() != nil {
					return fmt.Errorf("%w: %v", errClientAbort, c.Request.Context().Err())
				}
				if successCount > 0 {
					body, err := marshalModelsList(mergeModelsFetchResults(results))
					if err != nil {
						c.JSON(http.StatusBadGateway, gin.H{"error": "failed to encode models response"})
						return err
					}
					c.Data(http.StatusOK, "application/json", body)
					return nil
				}
				if allFailuresBlacklisted {
					lastErr = errors.New("all managed models providers failed and were blacklisted")
					continue candidateLoop
				}
				lastErr = firstFailureErr
				if firstFailureWasProxy {
					c.JSON(http.StatusBadGateway, gin.H{"error": "代理连接失败，请稍后重试"})
					return firstFailureErr
				}
				if firstFailureResponse != nil {
					writeModelsProviderResponse(c, firstFailureResponse)
					return firstFailureErr
				}
				c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("请求失败: %v", firstFailureErr)})
				return firstFailureErr
			}

			retryStrictAccountSelection := false
			for i, provider := range providers {
				fmt.Printf("[%s] 使用 Provider: %s | Platform: %s | Pool: %s | URL: %s\n",
					logPrefix, provider.Name, candidate, plan.pool.Name, provider.APIURL)

				response, fetchErr := prs.fetchModelsFromProvider(
					c.Request.Context(), c.Request.Header, c.Request.URL.RawQuery, provider, logPrefix,
				)
				if fetchErr == nil && response != nil && response.statusCode >= http.StatusOK && response.statusCode < http.StatusMultipleChoices {
					if !accountPool {
						fetchErr = applyModelsMappingToResponse(response, provider)
					}
				}
				if fetchErr == nil && response != nil && response.statusCode >= http.StatusOK && response.statusCode < http.StatusMultipleChoices {
					fmt.Printf("[%s] ✓ 成功: %s | HTTP %d\n", logPrefix, provider.Name, response.statusCode)
					prs.recordProviderSuccessForUser(plan.userID, candidate, plan.poolID, provider)
					writeModelsProviderResponse(c, response)
					return nil
				}

				if accountPool && fetchErr == nil && response != nil && isRequestScopedUpstream4xx(response.statusCode) {
					// This status describes the caller's request, not this account
					// key. Do not fail over or add an account-pool penalty.
					response, _ = sanitizeModelsFailure(response, nil, provider)
					response.header = clientErrorResponseHeaders(response.header)
					writeModelsProviderResponse(c, response)
					return nil
				}
				response, fetchErr = sanitizeModelsFailure(response, fetchErr, provider)
				if errors.Is(fetchErr, errClientAbort) {
					return fetchErr
				}
				lastErr = fetchErr
				if accountPool {
					sawAccountPoolFailure = true
				}
				fmt.Printf("[%s][WARN] Provider %s 模型列表失败: %v\n", logPrefix, provider.Name, fetchErr)
				if proxyErr, proxyFailure := isProxyRequestError(fetchErr); proxyFailure {
					if prs.proxyManager != nil {
						prs.proxyManager.InvalidateProxy(proxyErr.PoolKey, proxyErr.Node)
					}
					c.JSON(http.StatusBadGateway, gin.H{"error": "代理连接失败，请稍后重试"})
					return fetchErr
				}

				blacklistedAfterFailure := prs.recordProviderFailureForUser(plan.userID, candidate, plan.poolID, plan.pool, provider, fetchErr.Error())
				if accountPool && accountStickyRequest != nil && accountStickyRequest.providerID != 0 {
					// Rebuild after every account-key failure. The provisional binding
					// keeps A selected while it remains usable; blacklist/deletion lets
					// order() select the next key in a fresh plan.
					retryStrictAccountSelection = true
					break
				}
				if !blacklistedAfterFailure {
					if response != nil &&
						(response.statusCode < http.StatusOK || response.statusCode >= http.StatusMultipleChoices) {
						writeModelsProviderResponse(c, response)
						return fetchErr
					}
					c.JSON(http.StatusBadGateway, gin.H{"error": fmt.Sprintf("请求失败: %v", fetchErr)})
					return fetchErr
				}

				if prs.notificationService != nil && i+1 < len(providers) {
					prs.notificationService.NotifyProviderSwitch(SwitchNotification{
						UserID:       plan.userID,
						FromProvider: provider.Name,
						ToProvider:   providers[i+1].Name,
						Reason:       fetchErr.Error(),
						Platform:     candidate,
					})
				}
			}
			if retryStrictAccountSelection {
				continue
			}
			continue candidateLoop
		}
	}

	if sawAccountPoolFailure {
		c.JSON(http.StatusBadGateway, gin.H{"error": "号池中所有可用账号均请求失败，请稍后重试"})
		return lastErr
	}
	if sawAccountPoolUnavailable {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "号池暂无可用账号，请稍后重试"})
		return lastErr
	}
	if sawAllBlacklisted {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "所有可用于 /v1/models 的 provider 均在临时拉黑期"})
		return lastErr
	}
	if sawPoolResolved {
		c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("no providers available for /v1/models: %v", lastErr)})
		return lastErr
	}
	c.JSON(http.StatusForbidden, gin.H{"error": fmt.Sprintf("relay key 无权访问 /v1/models 的供应商池: %v", lastErr)})
	return lastErr
}

// modelsHandler 处理 /v1/models 请求（OpenAI-compatible API）
// 将请求转发到 relay key 绑定池子中当前可用的 provider，并注入 API Key。
func (prs *ProviderRelayService) modelsHandler(kind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		_ = prs.forwardModelsRequest(c, kind, "Models")
	}
}

// estimateInputTokens 在本地估算 Anthropic Messages 请求的输入 token 数。
// 用于上游不支持 /v1/messages/count_tokens 的场景。
// 中文按每字 1 token，英文按每 4 字符 1 token。
func estimateInputTokens(bodyBytes []byte) int {
	var body struct {
		System   interface{}     `json:"system"`
		Messages []interface{}   `json:"messages"`
		Tools    json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(bodyBytes, &body); err != nil {
		return 100
	}

	var totalChars int
	var cjkCount int

	extractText := func(v interface{}) string {
		if v == nil {
			return ""
		}
		switch val := v.(type) {
		case string:
			return val
		case []interface{}:
			var parts []string
			for _, item := range val {
				if s, ok := item.(string); ok {
					parts = append(parts, s)
				} else if m, ok := item.(map[string]interface{}); ok {
					if t, ok := m["type"].(string); ok && t == "text" {
						parts = append(parts, fmt.Sprint(m["text"]))
					}
				}
			}
			return strings.Join(parts, "\n")
		default:
			return fmt.Sprint(v)
		}
	}

	systemText := extractText(body.System)
	for _, ch := range systemText {
		if ch >= 0x4e00 && ch <= 0x9fff {
			cjkCount++
		}
		totalChars += len(string(ch))
	}

	for _, raw := range body.Messages {
		if m, ok := raw.(map[string]interface{}); ok {
			txt := fmt.Sprint(m["role"]) + "\n" + extractText(m["content"])
			for _, ch := range txt {
				if ch >= 0x4e00 && ch <= 0x9fff {
					cjkCount++
				}
				totalChars += len(string(ch))
			}
		}
	}

	if body.Tools != nil {
		totalChars += len(body.Tools)
	}

	otherCount := totalChars - cjkCount
	if otherCount < 0 {
		otherCount = 0
	}
	estimated := cjkCount + (otherCount / 4) + 20
	if estimated < 1 {
		estimated = 1
	}
	return estimated
}

// ========== RPC 方法：池子拉黑状态查询和清除 ==========

// ListProviderBlacklistStatus 返回指定池子内所有 provider 的拉黑状态（供前端展示）
func (prs *ProviderRelayService) ListProviderBlacklistStatus(platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatus(platform, poolID)
}

// ListProviderBlacklistStatusForUser 返回指定用户池子内所有 provider 的拉黑状态。
func (prs *ProviderRelayService) ListProviderBlacklistStatusForUser(userID, platform, poolID string) []ProviderPoolProviderPenalty {
	return prs.listProviderBlacklistStatusForUser(userID, platform, poolID)
}

// ClearProviderBlacklist 手动清除指定池子内某个 provider 的拉黑状态
func (prs *ProviderRelayService) ClearProviderBlacklist(platform, poolID string, providerID int64) {
	prs.clearProviderBlacklist(platform, poolID, providerID)
}

// ClearProviderBlacklistForUser 手动清除指定用户池子内某个 provider 的拉黑状态。
func (prs *ProviderRelayService) ClearProviderBlacklistForUser(userID, platform, poolID string, providerID int64) {
	prs.clearProviderBlacklistForUser(userID, platform, poolID, providerID)
}

// ClearAllProviderBlacklistsForUser clears all active blacklists in one user pool.
func (prs *ProviderRelayService) ClearAllProviderBlacklistsForUser(userID, platform, poolID string) {
	prs.clearAllProviderBlacklistsForUser(userID, platform, poolID)
}
