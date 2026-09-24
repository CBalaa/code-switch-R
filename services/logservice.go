package services

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/daodao97/xgo/xdb"
)

const timeLayout = "2006-01-02 15:04:05"

var beijingLocation = loadBeijingLocation()

const maxCompletedRequestLogs = 105

type LogService struct {
	relayKeys *CodexRelayKeyService
}

func NewLogService() *LogService {
	return &LogService{
		relayKeys: NewCodexRelayKeyService(),
	}
}

func (ls *LogService) RetryActiveRequest(id int64) ActiveRequestRetryResult {
	return ls.RetryActiveRequestForUser("", id)
}

func (ls *LogService) RetryActiveRequestForUser(userID string, id int64) ActiveRequestRetryResult {
	return defaultActiveRequestTracker.Retry(id, userID)
}

func (ls *LogService) ListActiveRequestLogsForUser(userID string) ([]ReqeustLog, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("用户 ID 不能为空")
	}

	activeLogs := defaultActiveRequestTracker.List("", "", userID)
	if len(activeLogs) == 0 {
		return activeLogs, nil
	}
	keyNames := ls.relayKeyNameMapForUser(userID)
	for i := range activeLogs {
		relayKeyID := strings.TrimSpace(activeLogs[i].RelayKeyID)
		activeLogs[i].RelayKeyID = relayKeyID
		activeLogs[i].RelayKeyName = relayKeyDisplayName(relayKeyID, keyNames)
	}
	return activeLogs, nil
}

func (ls *LogService) ListCompletedRequestLogsForUser(userID string, afterID int64, limit int) ([]ReqeustLog, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("用户 ID 不能为空")
	}
	if limit <= 0 || limit > maxCompletedRequestLogs {
		limit = maxCompletedRequestLogs
	}

	options := []xdb.Option{
		xdb.WhereEq("user_id", userID),
		xdb.OrderByDesc("id"),
		xdb.Limit(limit),
	}
	if afterID >= 0 {
		options = append(options, xdb.WhereGt("id", afterID))
	}
	records, err := xdb.New("request_log").Selects(options...)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return []ReqeustLog{}, nil
	}

	keyNames := ls.relayKeyNameMapForUser(userID)
	logs := make([]ReqeustLog, 0, len(records))
	for _, record := range records {
		relayKeyID := strings.TrimSpace(record.GetString("relay_key_id"))
		firstTextSec := record.GetFloat64("first_text_sec")
		firstTokenSec := record.GetFloat64("first_token_duration_sec")
		if firstTokenSec == 0 {
			firstTokenSec = firstTextSec
		}
		if firstTokenSec == 0 {
			firstTokenSec = record.GetFloat64("first_event_sec")
		}
		errorMessage := record.GetString("error_message")
		retryRequested := errorMessage == "重试" && record.GetInt("http_code") == 499
		logEntry := ReqeustLog{
			ID:                      record.GetInt64("id"),
			UserID:                  record.GetString("user_id"),
			Platform:                record.GetString("platform"),
			Model:                   record.GetString("model"),
			RequestedModel:          record.GetString("requested_model"),
			ResponseModel:           record.GetString("response_model"),
			RelayKeyName:            strings.TrimSpace(record.GetString("relay_key_name")),
			Provider:                record.GetString("provider"),
			RelayKeyID:              relayKeyID,
			HttpCode:                record.GetInt("http_code"),
			ErrorMessage:            errorMessage,
			InputTokens:             record.GetInt("input_tokens"),
			OutputTokens:            record.GetInt("output_tokens"),
			CacheCreateTokens:       record.GetInt("cache_create_tokens"),
			CacheReadTokens:         record.GetInt("cache_read_tokens"),
			ReasoningTokens:         record.GetInt("reasoning_tokens"),
			ExcludeFromTotalTraffic: record.GetBool("exclude_from_total"),
			CreatedAt:               formatCreatedAtBeijing(record),
			IsStream:                record.GetBool("is_stream"),
			DurationSec:             record.GetFloat64("duration_sec"),
			FirstTokenDurationSec:   firstTokenSec,
			ClientIP:                record.GetString("client_ip"),
			UpstreamHeaderSec:       record.GetFloat64("upstream_header_sec"),
			FirstEventSec:           record.GetFloat64("first_event_sec"),
			FirstTextSec:            firstTextSec,
			Status:                  requestLogStatusCompleted,
			RetryRequested:          retryRequested,
			TrafficTraceID:          record.GetString("traffic_trace_id"),
			ClientNetworkScope:      record.GetString("client_network_scope"),
			ClientRequestBytes:      record.GetInt64("client_request_bytes"),
			ClientResponseBytes:     record.GetInt64("client_response_bytes"),
			UpstreamRequestBytes:    record.GetInt64("upstream_request_bytes"),
			UpstreamResponseBytes:   record.GetInt64("upstream_response_bytes"),
			RetryRequestBytes:       record.GetInt64("retry_request_bytes"),
			RetryResponseBytes:      record.GetInt64("retry_response_bytes"),
			UpstreamAttempts:        record.GetInt("upstream_attempts"),
			PublicIngressBytes:      record.GetInt64("public_ingress_bytes"),
			PublicEgressBytes:       record.GetInt64("public_egress_bytes"),
			LocalIngressBytes:       record.GetInt64("local_ingress_bytes"),
			LocalEgressBytes:        record.GetInt64("local_egress_bytes"),
		}
		if logEntry.RelayKeyName == "" {
			logEntry.RelayKeyName = relayKeyDisplayName(relayKeyID, keyNames)
		}
		logs = append(logs, logEntry)
	}
	return logs, nil
}

func (ls *LogService) relayKeyNameMapForUser(userID string) map[string]string {
	if ls == nil || ls.relayKeys == nil {
		return nil
	}
	var keys []CodexRelayKeyListItem
	var err error
	if strings.TrimSpace(userID) == "" {
		keys, err = ls.relayKeys.ListKeys()
	} else {
		keys, err = ls.relayKeys.ListKeysForUser(userID)
	}
	if err != nil {
		return nil
	}
	names := make(map[string]string, len(keys))
	for _, key := range keys {
		id := strings.TrimSpace(key.ID)
		if id != "" {
			names[id] = strings.TrimSpace(key.Name)
		}
	}
	return names
}

func relayKeyDisplayName(id string, names map[string]string) string {
	id = strings.TrimSpace(id)
	if id == "" {
		return ""
	}
	if name := strings.TrimSpace(names[id]); name != "" {
		return name
	}
	return id
}

func (ls *LogService) StatsSince(platform string) (LogStats, error) {
	return ls.StatsSinceForUser("", platform)
}

func (ls *LogService) StatsSinceForUser(userID string, platform string) (LogStats, error) {
	const (
		seriesBuckets  = 48
		bucketDuration = 30 * time.Minute
	)

	stats := LogStats{
		Series: make([]LogStatsSeries, 0, seriesBuckets),
	}
	loc := beijingLocation
	now := time.Now().In(loc)
	seriesStart := startOfDay(now)
	seriesEnd := seriesStart.Add(24 * time.Hour)
	queryStart := seriesStart.In(time.UTC).Format(timeLayout)
	queryEnd := seriesEnd.In(time.UTC).Format(timeLayout)

	db, err := xdb.DB("default")
	if err != nil {
		return stats, err
	}
	if err := requireRequestLogRollupReady(db); err != nil {
		return stats, err
	}

	query := `
		SELECT
			bucket_start_utc,
			COALESCE(SUM(total_requests), 0) AS total_requests,
			COALESCE(SUM(input_tokens), 0) AS input_tokens,
			COALESCE(SUM(output_tokens), 0) AS output_tokens,
			COALESCE(SUM(reasoning_tokens), 0) AS reasoning_tokens,
			COALESCE(SUM(cache_create_tokens), 0) AS cache_create_tokens,
			COALESCE(SUM(cache_read_tokens), 0) AS cache_read_tokens
		FROM request_log_rollup_30m
		WHERE bucket_start_utc >= ?
			AND bucket_start_utc < ?`
	args := []any{queryStart, queryEnd}
	if platform != "" {
		query += " AND platform = ?"
		args = append(args, platform)
	}
	if strings.TrimSpace(userID) != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}
	query += " GROUP BY bucket_start_utc ORDER BY bucket_start_utc ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return stats, err
	}
	defer rows.Close()

	series := make([]LogStatsSeries, seriesBuckets)
	for i := 0; i < seriesBuckets; i++ {
		bucketTime := seriesStart.Add(time.Duration(i) * bucketDuration)
		series[i].Day = bucketTime.Format(timeLayout)
	}

	for rows.Next() {
		var bucketStartRaw string
		var bucket LogStatsSeries
		if err := rows.Scan(
			&bucketStartRaw,
			&bucket.TotalRequests,
			&bucket.InputTokens,
			&bucket.OutputTokens,
			&bucket.ReasoningTokens,
			&bucket.CacheCreateTokens,
			&bucket.CacheReadTokens,
		); err != nil {
			return stats, err
		}
		bucketStart, err := time.ParseInLocation(timeLayout, bucketStartRaw, time.UTC)
		if err != nil {
			return stats, fmt.Errorf("解析 request_log rollup bucket %q 失败: %w", bucketStartRaw, err)
		}
		bucketIndex := int(bucketStart.Sub(seriesStart.UTC()) / bucketDuration)
		if bucketIndex < 0 || bucketIndex >= seriesBuckets {
			continue
		}
		bucket.Day = series[bucketIndex].Day
		series[bucketIndex] = bucket
		stats.TotalRequests += bucket.TotalRequests
		stats.InputTokens += bucket.InputTokens
		stats.OutputTokens += bucket.OutputTokens
		stats.ReasoningTokens += bucket.ReasoningTokens
		stats.CacheCreateTokens += bucket.CacheCreateTokens
		stats.CacheReadTokens += bucket.CacheReadTokens
	}
	if err := rows.Err(); err != nil {
		return stats, err
	}
	stats.Series = append(stats.Series, series...)

	return stats, nil
}

func (ls *LogService) ProviderDailyStats(platform string) ([]ProviderDailyStat, error) {
	return ls.ProviderDailyStatsForUser("", platform)
}

func (ls *LogService) ProviderDailyStatsForUser(userID string, platform string) ([]ProviderDailyStat, error) {
	loc := beijingLocation
	start := startOfDay(time.Now().In(loc))
	end := start.Add(24 * time.Hour)
	queryStart := start.In(time.UTC).Format(timeLayout)
	queryEnd := end.In(time.UTC).Format(timeLayout)
	query := `
		SELECT
			COALESCE(provider, '') AS provider,
			COUNT(*) AS total_requests,
			COALESCE(SUM(CASE WHEN http_code >= 200 AND http_code < 300 THEN 1 ELSE 0 END), 0) AS successful_requests,
			COALESCE(SUM(CASE WHEN http_code >= 200 AND http_code < 300 THEN 0 ELSE 1 END), 0) AS failed_requests,
			COALESCE(SUM(CASE WHEN COALESCE(exclude_from_total, 0) = 0 THEN COALESCE(input_tokens, 0) ELSE 0 END), 0) AS input_tokens,
			COALESCE(SUM(CASE WHEN COALESCE(exclude_from_total, 0) = 0 THEN COALESCE(output_tokens, 0) ELSE 0 END), 0) AS output_tokens,
			COALESCE(SUM(CASE WHEN COALESCE(exclude_from_total, 0) = 0 THEN COALESCE(reasoning_tokens, 0) ELSE 0 END), 0) AS reasoning_tokens,
			COALESCE(SUM(CASE WHEN COALESCE(exclude_from_total, 0) = 0 THEN COALESCE(cache_create_tokens, 0) ELSE 0 END), 0) AS cache_create_tokens,
			COALESCE(SUM(CASE WHEN COALESCE(exclude_from_total, 0) = 0 THEN COALESCE(cache_read_tokens, 0) ELSE 0 END), 0) AS cache_read_tokens
		FROM request_log
		WHERE created_at >= ?
			AND created_at < ?
			AND (
				(DATETIME(created_at) IS NOT NULL AND DATETIME(created_at) >= ? AND DATETIME(created_at) < ?)
				OR (DATETIME(created_at) IS NULL AND SUBSTR(TRIM(COALESCE(created_at, '')), 1, 10) = ?)
			)`
	args := []any{queryStart, queryEnd, queryStart, queryEnd, start.Format("2006-01-02")}
	if platform != "" {
		query += " AND platform = ?"
		args = append(args, platform)
	}
	if strings.TrimSpace(userID) != "" {
		query += " AND user_id = ?"
		args = append(args, userID)
	}
	query += " GROUP BY provider"

	db, err := xdb.DB("default")
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		if isNoSuchTableErr(err) {
			return []ProviderDailyStat{}, nil
		}
		return nil, err
	}
	defer rows.Close()

	statMap := map[string]*ProviderDailyStat{}
	for rows.Next() {
		var provider string
		var rowStat ProviderDailyStat
		if err := rows.Scan(
			&provider,
			&rowStat.TotalRequests,
			&rowStat.SuccessfulRequests,
			&rowStat.FailedRequests,
			&rowStat.InputTokens,
			&rowStat.OutputTokens,
			&rowStat.ReasoningTokens,
			&rowStat.CacheCreateTokens,
			&rowStat.CacheReadTokens,
		); err != nil {
			return nil, err
		}
		provider = strings.TrimSpace(provider)
		if provider == "" {
			provider = "(unknown)"
		}
		stat := statMap[provider]
		if stat == nil {
			stat = &ProviderDailyStat{Provider: provider}
			statMap[provider] = stat
		}
		stat.TotalRequests += rowStat.TotalRequests
		stat.SuccessfulRequests += rowStat.SuccessfulRequests
		stat.FailedRequests += rowStat.FailedRequests
		stat.InputTokens += rowStat.InputTokens
		stat.OutputTokens += rowStat.OutputTokens
		stat.ReasoningTokens += rowStat.ReasoningTokens
		stat.CacheCreateTokens += rowStat.CacheCreateTokens
		stat.CacheReadTokens += rowStat.CacheReadTokens
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	stats := make([]ProviderDailyStat, 0, len(statMap))
	for _, stat := range statMap {
		if stat.TotalRequests > 0 {
			stat.SuccessRate = float64(stat.SuccessfulRequests) / float64(stat.TotalRequests)
		}
		stats = append(stats, *stat)
	}
	sort.Slice(stats, func(i, j int) bool {
		if stats[i].TotalRequests == stats[j].TotalRequests {
			return stats[i].Provider < stats[j].Provider
		}
		return stats[i].TotalRequests > stats[j].TotalRequests
	})
	return stats, nil
}

func (ls *LogService) ListHTTPErrorConsoleLogsForUser(userID string, limit int, since time.Time) ([]ConsoleLog, error) {
	logs, _, err := ls.ListHTTPErrorConsoleLogsForUserAfterID(userID, 0, limit, since)
	return logs, err
}

// ListHTTPErrorConsoleLogsForUserAfterID uses request_log.id as its cursor so
// multiple errors created in the same second cannot be skipped by polling.
func (ls *LogService) ListHTTPErrorConsoleLogsForUserAfterID(userID string, afterID int64, limit int, since time.Time) ([]ConsoleLog, int64, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, afterID, errors.New("用户 ID 不能为空")
	}
	limit = normalizeConsoleLogLimit(limit)

	query := `
		SELECT
			id,
			COALESCE(platform, ''),
			COALESCE(model, ''),
			COALESCE(provider, ''),
			COALESCE(relay_key_id, ''),
			COALESCE(http_code, 0),
			COALESCE(error_message, ''),
			COALESCE(duration_sec, 0),
			COALESCE(created_at, '')
		FROM request_log
		WHERE user_id = ?
			AND http_code >= 400
			AND id > ?`
	args := []any{userID, afterID}
	if !since.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, since.UTC().Format(timeLayout))
	}
	query += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)

	db, err := xdb.DB("default")
	if err != nil {
		return nil, afterID, err
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		if isNoSuchTableErr(err) {
			return []ConsoleLog{}, afterID, nil
		}
		return nil, afterID, err
	}
	defer rows.Close()

	type consoleRequestLog struct {
		id           int64
		platform     string
		model        string
		provider     string
		relayKeyID   string
		httpCode     int
		errorMessage string
		durationSec  float64
		createdAt    string
	}
	records := make([]consoleRequestLog, 0, limit)
	for rows.Next() {
		var record consoleRequestLog
		if err := rows.Scan(
			&record.id,
			&record.platform,
			&record.model,
			&record.provider,
			&record.relayKeyID,
			&record.httpCode,
			&record.errorMessage,
			&record.durationSec,
			&record.createdAt,
		); err != nil {
			return nil, afterID, err
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, afterID, err
	}

	keyNames := ls.relayKeyNameMapForUser(userID)
	logs := make([]ConsoleLog, 0, len(records))
	nextID := afterID
	for i := len(records) - 1; i >= 0; i-- {
		record := records[i]
		if record.id > nextID {
			nextID = record.id
		}
		createdAt, _ := parseLogTimestamp(record.createdAt)
		if createdAt.IsZero() {
			createdAt = time.Now().In(beijingLocation)
		}
		level := "WARN"
		if record.httpCode >= 500 {
			level = "ERROR"
		}
		relayKeyID := strings.TrimSpace(record.relayKeyID)
		relayKeyName := relayKeyDisplayName(relayKeyID, keyNames)
		message := fmt.Sprintf(
			"HTTP %d | platform=%s provider=%s model=%s key=%s duration=%.2fs request_id=%d | %s",
			record.httpCode,
			emptyAsUnknown(record.platform),
			emptyAsUnknown(record.provider),
			emptyAsUnknown(record.model),
			emptyAsUnknown(relayKeyName),
			record.durationSec,
			record.id,
			emptyAsUnknown(record.errorMessage),
		)
		logs = append(logs, ConsoleLog{
			Timestamp: createdAt,
			Level:     level,
			Message:   message,
		})
	}
	return logs, nextID, nil
}

func emptyAsUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "(unknown)"
	}
	return value
}

func parseCreatedAt(record xdb.Record) (time.Time, bool) {
	raw := strings.TrimSpace(record.GetString("created_at"))
	if raw != "" {
		if parsed, hasTime := parseLogTimestamp(raw); !parsed.IsZero() {
			return parsed, hasTime
		}
	}
	if t := record.GetTime("created_at"); t != nil {
		return t.In(beijingLocation), true
	}
	return time.Time{}, false
}

func parseLogTimestamp(raw string) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	layouts := []string{
		timeLayout,
		time.RFC3339,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05 MST",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.In(beijingLocation), true
		}
		if parsed, err := time.ParseInLocation(layout, raw, beijingLocation); err == nil {
			return parsed.In(beijingLocation), true
		}
	}

	if normalized := strings.Replace(raw, " ", "T", 1); normalized != raw {
		if parsed, err := time.Parse(time.RFC3339, normalized); err == nil {
			return parsed.In(beijingLocation), true
		}
	}

	if len(raw) >= len("2006-01-02") {
		if parsed, err := time.ParseInLocation("2006-01-02", raw[:10], beijingLocation); err == nil {
			return parsed, false
		}
	}

	return time.Time{}, false
}

func parseTimeInput(value string) (time.Time, error) {
	raw := strings.TrimSpace(value)
	if raw == "" {
		return startOfDay(time.Now().In(beijingLocation)), nil
	}
	layouts := []string{
		time.RFC3339,
		timeLayout,
		"2006-01-02T15:04:05",
		"2006-01-02 15:04:05 -0700",
		"2006-01-02 15:04:05 -0700 MST",
		"2006-01-02 15:04:05 MST",
		"2006-01-02T15:04:05-0700",
	}
	for _, layout := range layouts {
		if parsed, err := time.Parse(layout, raw); err == nil {
			return parsed.In(beijingLocation), nil
		}
		if parsed, err := time.ParseInLocation(layout, raw, beijingLocation); err == nil {
			return parsed.In(beijingLocation), nil
		}
	}
	if normalized := strings.Replace(raw, " ", "T", 1); normalized != raw {
		if parsed, err := time.Parse(time.RFC3339, normalized); err == nil {
			return parsed.In(beijingLocation), nil
		}
	}
	if len(raw) >= len("2006-01-02") {
		if parsed, err := time.ParseInLocation("2006-01-02", raw[:10], beijingLocation); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("invalid time format: %s", raw)
}

func dayFromTimestamp(value string) string {
	if parsed, _ := parseLogTimestamp(value); !parsed.IsZero() {
		return parsed.Format("2006-01-02")
	}
	value = strings.TrimSpace(value)
	if len(value) >= len("2006-01-02") {
		return value[:10]
	}
	return value
}

func startOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, t.Location())
}

func loadBeijingLocation() *time.Location {
	loc, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		return time.FixedZone("Asia/Shanghai", 8*60*60)
	}
	return loc
}

func formatCreatedAtBeijing(record xdb.Record) string {
	createdAt, hasTime := parseCreatedAt(record)
	if !createdAt.IsZero() {
		if hasTime {
			return createdAt.Format(timeLayout)
		}
		return createdAt.Format("2006-01-02")
	}
	return record.GetString("created_at")
}

func startOfHour(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, t.Hour(), 0, 0, 0, t.Location())
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func isNoSuchTableErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "no such table")
}

type LogStats struct {
	TotalRequests     int64            `json:"total_requests"`
	InputTokens       int64            `json:"input_tokens"`
	OutputTokens      int64            `json:"output_tokens"`
	ReasoningTokens   int64            `json:"reasoning_tokens"`
	CacheCreateTokens int64            `json:"cache_create_tokens"`
	CacheReadTokens   int64            `json:"cache_read_tokens"`
	Series            []LogStatsSeries `json:"series"`
}

type ProviderDailyStat struct {
	Provider           string  `json:"provider"`
	TotalRequests      int64   `json:"total_requests"`
	SuccessfulRequests int64   `json:"successful_requests"`
	FailedRequests     int64   `json:"failed_requests"`
	SuccessRate        float64 `json:"success_rate"`
	InputTokens        int64   `json:"input_tokens"`
	OutputTokens       int64   `json:"output_tokens"`
	ReasoningTokens    int64   `json:"reasoning_tokens"`
	CacheCreateTokens  int64   `json:"cache_create_tokens"`
	CacheReadTokens    int64   `json:"cache_read_tokens"`
}

type LogStatsSeries struct {
	Day               string `json:"day"`
	TotalRequests     int64  `json:"total_requests"`
	InputTokens       int64  `json:"input_tokens"`
	OutputTokens      int64  `json:"output_tokens"`
	ReasoningTokens   int64  `json:"reasoning_tokens"`
	CacheCreateTokens int64  `json:"cache_create_tokens"`
	CacheReadTokens   int64  `json:"cache_read_tokens"`
}
