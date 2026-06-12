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

type LogService struct {
	relayKeys *CodexRelayKeyService
}

func NewLogService() *LogService {
	return &LogService{
		relayKeys: NewCodexRelayKeyService(),
	}
}

func (ls *LogService) ListRequestLogs(platform string, provider string, limit int) ([]ReqeustLog, error) {
	return ls.ListRequestLogsForUser("", platform, provider, limit)
}

func (ls *LogService) ListRequestLogsForUser(userID string, platform string, provider string, limit int) ([]ReqeustLog, error) {
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	model := xdb.New("request_log")
	options := []xdb.Option{
		xdb.OrderByDesc("id"),
		xdb.Limit(limit),
	}
	if platform != "" {
		options = append(options, xdb.WhereEq("platform", platform))
	}
	if provider != "" {
		options = append(options, xdb.WhereEq("provider", provider))
	}
	if strings.TrimSpace(userID) != "" {
		options = append(options, xdb.WhereEq("user_id", userID))
	}
	records, err := model.Selects(options...)
	if err != nil {
		return nil, err
	}
	keyNames := ls.relayKeyNameMapForUser(userID)
	logs := make([]ReqeustLog, 0, len(records))
	for _, record := range records {
		relayKeyID := strings.TrimSpace(record.GetString("relay_key_id"))
		logEntry := ReqeustLog{
			ID:                record.GetInt64("id"),
			UserID:            record.GetString("user_id"),
			Platform:          record.GetString("platform"),
			Model:             record.GetString("model"),
			Provider:          record.GetString("provider"),
			RelayKeyID:        relayKeyID,
			RelayKeyName:      relayKeyDisplayName(relayKeyID, keyNames),
			HttpCode:          record.GetInt("http_code"),
			InputTokens:       record.GetInt("input_tokens"),
			OutputTokens:      record.GetInt("output_tokens"),
			CacheCreateTokens: record.GetInt("cache_create_tokens"),
			CacheReadTokens:   record.GetInt("cache_read_tokens"),
			ReasoningTokens:   record.GetInt("reasoning_tokens"),
			CreatedAt:         formatCreatedAtBeijing(record),
			IsStream:          record.GetBool("is_stream"),
			DurationSec:       record.GetFloat64("duration_sec"),
			UpstreamHeaderSec: record.GetFloat64("upstream_header_sec"),
			FirstEventSec:     record.GetFloat64("first_event_sec"),
			FirstTextSec:      record.GetFloat64("first_text_sec"),
		}
		logs = append(logs, logEntry)
	}
	return logs, nil
}

func (ls *LogService) relayKeyNameMap() map[string]string {
	return ls.relayKeyNameMapForUser("")
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

func (ls *LogService) ListProviders(platform string) ([]string, error) {
	return ls.ListProvidersForUser("", platform)
}

func (ls *LogService) ListProvidersForUser(userID string, platform string) ([]string, error) {
	model := xdb.New("request_log")
	options := []xdb.Option{
		xdb.Field("DISTINCT provider as provider"),
		xdb.WhereNotEq("provider", ""),
		xdb.OrderByAsc("provider"),
	}
	if platform != "" {
		options = append(options, xdb.WhereEq("platform", platform))
	}
	if strings.TrimSpace(userID) != "" {
		options = append(options, xdb.WhereEq("user_id", userID))
	}
	records, err := model.Selects(options...)
	if err != nil {
		return nil, err
	}
	providers := make([]string, 0, len(records))
	for _, record := range records {
		name := strings.TrimSpace(record.GetString("provider"))
		if name != "" {
			providers = append(providers, name)
		}
	}
	return providers, nil
}

func (ls *LogService) StatsSince(platform string) (LogStats, error) {
	return ls.StatsSinceForUser("", platform)
}

func (ls *LogService) StatsSinceForUser(userID string, platform string) (LogStats, error) {
	const seriesHours = 24

	stats := LogStats{
		Series: make([]LogStatsSeries, 0, seriesHours),
	}
	loc := beijingLocation
	now := time.Now().In(loc)
	model := xdb.New("request_log")
	seriesStart := startOfDay(now)
	seriesEnd := seriesStart.Add(seriesHours * time.Hour)
	queryStart := seriesStart.In(time.UTC).Format(timeLayout)
	queryEnd := seriesEnd.In(time.UTC).Format(timeLayout)
	options := []xdb.Option{
		xdb.WhereGte("created_at", queryStart),
		xdb.WhereLt("created_at", queryEnd),
		xdb.Field(
			"model",
			"input_tokens",
			"output_tokens",
			"reasoning_tokens",
			"cache_create_tokens",
			"cache_read_tokens",
			"created_at",
		),
		xdb.OrderByAsc("created_at"),
	}
	if platform != "" {
		options = append(options, xdb.WhereEq("platform", platform))
	}
	if strings.TrimSpace(userID) != "" {
		options = append(options, xdb.WhereEq("user_id", userID))
	}
	records, err := model.Selects(options...)
	if err != nil {
		if errors.Is(err, xdb.ErrNotFound) || isNoSuchTableErr(err) {
			return stats, nil
		}
		return stats, err
	}

	seriesBuckets := make([]*LogStatsSeries, seriesHours)
	for i := 0; i < seriesHours; i++ {
		bucketTime := seriesStart.Add(time.Duration(i) * time.Hour)
		seriesBuckets[i] = &LogStatsSeries{
			Day: bucketTime.Format(timeLayout),
		}
	}

	for _, record := range records {
		createdAt, hasTime := parseCreatedAt(record)
		dayKey := dayFromTimestamp(record.GetString("created_at"))
		isToday := dayKey == seriesStart.Format("2006-01-02")

		if hasTime {
			if createdAt.Before(seriesStart) || !createdAt.Before(seriesEnd) {
				continue
			}
		} else {
			if !isToday {
				continue
			}
			createdAt = seriesStart
		}

		bucketIndex := 0
		if hasTime {
			bucketIndex = int(createdAt.Sub(seriesStart) / time.Hour)
			if bucketIndex < 0 {
				bucketIndex = 0
			}
			if bucketIndex >= seriesHours {
				bucketIndex = seriesHours - 1
			}
		}
		bucket := seriesBuckets[bucketIndex]
		input := record.GetInt("input_tokens")
		output := record.GetInt("output_tokens")
		reasoning := record.GetInt("reasoning_tokens")
		cacheCreate := record.GetInt("cache_create_tokens")
		cacheRead := record.GetInt("cache_read_tokens")
		bucket.TotalRequests++
		bucket.InputTokens += int64(input)
		bucket.OutputTokens += int64(output)
		bucket.ReasoningTokens += int64(reasoning)
		bucket.CacheCreateTokens += int64(cacheCreate)
		bucket.CacheReadTokens += int64(cacheRead)

		if createdAt.IsZero() {
			continue
		}
		stats.TotalRequests++
		stats.InputTokens += int64(input)
		stats.OutputTokens += int64(output)
		stats.ReasoningTokens += int64(reasoning)
		stats.CacheCreateTokens += int64(cacheCreate)
		stats.CacheReadTokens += int64(cacheRead)
	}

	for i := 0; i < seriesHours; i++ {
		if bucket := seriesBuckets[i]; bucket != nil {
			stats.Series = append(stats.Series, *bucket)
		} else {
			bucketTime := seriesStart.Add(time.Duration(i) * time.Hour)
			stats.Series = append(stats.Series, LogStatsSeries{
				Day: bucketTime.Format(timeLayout),
			})
		}
	}

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
	model := xdb.New("request_log")
	options := []xdb.Option{
		xdb.WhereGte("created_at", queryStart),
		xdb.WhereLt("created_at", queryEnd),
		xdb.Field(
			"provider",
			"model",
			"http_code",
			"input_tokens",
			"output_tokens",
			"reasoning_tokens",
			"cache_create_tokens",
			"cache_read_tokens",
			"created_at",
		),
	}
	if platform != "" {
		options = append(options, xdb.WhereEq("platform", platform))
	}
	if strings.TrimSpace(userID) != "" {
		options = append(options, xdb.WhereEq("user_id", userID))
	}
	records, err := model.Selects(options...)
	if err != nil {
		if errors.Is(err, xdb.ErrNotFound) || isNoSuchTableErr(err) {
			return []ProviderDailyStat{}, nil
		}
		return nil, err
	}
	statMap := map[string]*ProviderDailyStat{}
	for _, record := range records {
		provider := strings.TrimSpace(record.GetString("provider"))
		if provider == "" {
			provider = "(unknown)"
		}
		createdAt, hasTime := parseCreatedAt(record)
		if hasTime {
			if createdAt.Before(start) || !createdAt.Before(end) {
				continue
			}
		} else {
			dayKey := dayFromTimestamp(record.GetString("created_at"))
			if dayKey != start.Format("2006-01-02") {
				continue
			}
		}
		stat := statMap[provider]
		if stat == nil {
			stat = &ProviderDailyStat{Provider: provider}
			statMap[provider] = stat
		}
		httpCode := record.GetInt("http_code")
		input := record.GetInt("input_tokens")
		output := record.GetInt("output_tokens")
		reasoning := record.GetInt("reasoning_tokens")
		cacheCreate := record.GetInt("cache_create_tokens")
		cacheRead := record.GetInt("cache_read_tokens")
		stat.TotalRequests++
		// 只有 HTTP 200-299 才算成功，其他（包括 0）都算失败
		if httpCode >= 200 && httpCode < 300 {
			stat.SuccessfulRequests++
		} else {
			stat.FailedRequests++
		}
		stat.InputTokens += int64(input)
		stat.OutputTokens += int64(output)
		stat.ReasoningTokens += int64(reasoning)
		stat.CacheCreateTokens += int64(cacheCreate)
		stat.CacheReadTokens += int64(cacheRead)
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
