package services

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// AccountPoolSchedule repeats every week on the Beijing clock. The end
// minute is included; 00:00–23:59 therefore opens an entire calendar day.
type AccountPoolSchedule struct {
	Enabled bool                        `json:"enabled"`
	Windows []AccountPoolScheduleWindow `json:"windows"`
}

type AccountPoolScheduleWindow struct {
	Weekday   int    `json:"weekday"` // ISO weekday: Monday=1, Sunday=7.
	StartTime string `json:"startTime"`
	EndTime   string `json:"endTime"`
}

type accountPoolScheduleEvaluation struct {
	Enabled      bool
	IsOpen       bool
	NextChangeAt time.Time
}

// accountPoolScheduleClosedError describes a local admission decision, not
// an upstream account failure. Callers must not count or blacklist it.
type accountPoolScheduleClosedError struct {
	PoolID     string
	NextOpenAt time.Time
	Cause      error
}

func (e *accountPoolScheduleClosedError) Error() string {
	if e.Cause != nil {
		return "号池定时开放配置无效，暂不可调用"
	}
	message := "号池当前不在开放时段（北京时间）"
	if !e.NextOpenAt.IsZero() {
		message += "，下次开放：" + e.NextOpenAt.In(beijingLocation).Format("2006-01-02 15:04")
	}
	return message
}

func (e *accountPoolScheduleClosedError) Unwrap() error { return e.Cause }

func accountPoolScheduleMinute(value string) (int, error) {
	// Parsing alone accepts single-digit hours, which the persisted contract
	// deliberately excludes.
	if len(value) != 5 || value[2] != ':' || value[0] < '0' || value[0] > '2' ||
		value[1] < '0' || value[1] > '9' || value[3] < '0' || value[3] > '5' ||
		value[4] < '0' || value[4] > '9' {
		return 0, errors.New("时间必须为 HH:mm 格式（00:00–23:59）")
	}
	hour := int(value[0]-'0')*10 + int(value[1]-'0')
	if hour > 23 {
		return 0, errors.New("时间必须为 HH:mm 格式（00:00–23:59）")
	}
	return hour*60 + int(value[3]-'0')*10 + int(value[4]-'0'), nil
}

type accountPoolScheduleInterval struct{ start, end int }

func accountPoolScheduleIntervals(schedule *AccountPoolSchedule) ([]accountPoolScheduleInterval, error) {
	if schedule.Enabled && len(schedule.Windows) == 0 {
		return nil, errors.New("启用定时开放时至少需要一个开放时段")
	}
	intervals := make([]accountPoolScheduleInterval, 0, len(schedule.Windows))
	for index, window := range schedule.Windows {
		if window.Weekday < 1 || window.Weekday > 7 {
			return nil, fmt.Errorf("第 %d 个开放时段的星期必须为 1–7", index+1)
		}
		start, err := accountPoolScheduleMinute(window.StartTime)
		if err != nil {
			return nil, fmt.Errorf("第 %d 个开放时段的开始%s", index+1, err)
		}
		end, err := accountPoolScheduleMinute(window.EndTime)
		if err != nil {
			return nil, fmt.Errorf("第 %d 个开放时段的结束%s", index+1, err)
		}
		if start > end {
			return nil, fmt.Errorf("第 %d 个开放时段不支持跨日，请拆成当天和次日两个时段", index+1)
		}
		dayOffset := (window.Weekday - 1) * 24 * 60
		intervals = append(intervals, accountPoolScheduleInterval{start: dayOffset + start, end: dayOffset + end + 1})
	}
	sort.Slice(intervals, func(i, j int) bool {
		if intervals[i].start == intervals[j].start {
			return intervals[i].end < intervals[j].end
		}
		return intervals[i].start < intervals[j].start
	})
	merged := make([]accountPoolScheduleInterval, 0, len(intervals))
	for _, interval := range intervals {
		if len(merged) == 0 || interval.start > merged[len(merged)-1].end {
			merged = append(merged, interval)
			continue
		}
		if interval.end > merged[len(merged)-1].end {
			merged[len(merged)-1].end = interval.end
		}
	}
	return merged, nil
}

func normalizeAndValidateAccountPoolSchedule(schedule *AccountPoolSchedule) error {
	if schedule == nil {
		return nil
	}
	for index := range schedule.Windows {
		schedule.Windows[index].StartTime = strings.TrimSpace(schedule.Windows[index].StartTime)
		schedule.Windows[index].EndTime = strings.TrimSpace(schedule.Windows[index].EndTime)
	}
	if _, err := accountPoolScheduleIntervals(schedule); err != nil {
		return err
	}
	if schedule.Windows == nil {
		schedule.Windows = []AccountPoolScheduleWindow{}
	}
	return nil
}

// evaluateAccountPoolSchedule treats omitted and disabled schedules as always
// open. Invalid enabled schedules return IsOpen=false and an error, so stale
// or hand-edited data can never silently bypass admission checks.
func evaluateAccountPoolSchedule(pool *ProviderPool, now time.Time) (accountPoolScheduleEvaluation, error) {
	result := accountPoolScheduleEvaluation{IsOpen: true}
	if pool == nil || normalizedProviderPoolType(pool.PoolType) != ProviderPoolTypeAccount ||
		pool.AccountPoolConfig == nil || pool.AccountPoolConfig.Schedule == nil || !pool.AccountPoolConfig.Schedule.Enabled {
		return result, nil
	}
	result.Enabled = true
	result.IsOpen = false
	intervals, err := accountPoolScheduleIntervals(pool.AccountPoolConfig.Schedule)
	if err != nil {
		return result, err
	}
	const weekMinutes = 7 * 24 * 60
	if len(intervals) == 1 && intervals[0].start == 0 && intervals[0].end == weekMinutes {
		result.IsOpen = true
		return result, nil
	}
	localNow := now.In(beijingLocation)
	weekday := (int(localNow.Weekday()) + 6) % 7
	minute := weekday*24*60 + localNow.Hour()*60 + localNow.Minute()
	dayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, beijingLocation)
	weekStart := dayStart.AddDate(0, 0, -weekday)
	for _, interval := range intervals {
		if minute >= interval.start && minute < interval.end {
			result.IsOpen = true
			boundary := interval.end
			// The final Sunday interval and first Monday interval can be one
			// continuous opening even though the weekly representation splits it.
			if boundary == weekMinutes && intervals[0].start == 0 {
				boundary += intervals[0].end
			}
			result.NextChangeAt = weekStart.Add(time.Duration(boundary) * time.Minute)
			return result, nil
		}
		if interval.start > minute {
			result.NextChangeAt = weekStart.Add(time.Duration(interval.start) * time.Minute)
			return result, nil
		}
	}
	result.NextChangeAt = weekStart.Add(time.Duration(weekMinutes+intervals[0].start) * time.Minute)
	return result, nil
}

func checkAccountPoolScheduleOpen(pool *ProviderPool, now time.Time) error {
	result, err := evaluateAccountPoolSchedule(pool, now)
	if err == nil && result.IsOpen {
		return nil
	}
	poolID := ""
	if pool != nil {
		poolID = pool.ID
	}
	return &accountPoolScheduleClosedError{PoolID: poolID, NextOpenAt: result.NextChangeAt, Cause: err}
}

type AccountPoolScheduleStatus struct {
	PoolID       string `json:"poolId"`
	Enabled      bool   `json:"enabled"`
	IsOpen       bool   `json:"isOpen"`
	NextChangeAt string `json:"nextChangeAt,omitempty"`
}

type AccountPoolScheduleStatuses struct {
	ServerNow string                      `json:"serverNow"`
	Statuses  []AccountPoolScheduleStatus `json:"statuses"`
}

// GetAccountPoolScheduleStatuses returns only runtime scheduling metadata;
// account credentials and upstream URLs are never included.
func (s *ProviderPoolService) GetAccountPoolScheduleStatuses(platform string) (*AccountPoolScheduleStatuses, error) {
	var pools []ProviderPool
	var err error
	if platform == "" {
		pools, err = s.ListAllPools()
	} else {
		pools, err = s.ListPools(platform)
	}
	if err != nil {
		return nil, err
	}
	now := time.Now()
	result := &AccountPoolScheduleStatuses{
		ServerNow: now.In(beijingLocation).Format(time.RFC3339Nano),
		Statuses:  make([]AccountPoolScheduleStatus, 0),
	}
	for index := range pools {
		pool := &pools[index]
		if normalizedProviderPoolType(pool.PoolType) != ProviderPoolTypeAccount {
			continue
		}
		evaluation, _ := evaluateAccountPoolSchedule(pool, now)
		status := AccountPoolScheduleStatus{PoolID: pool.ID, Enabled: evaluation.Enabled, IsOpen: evaluation.IsOpen}
		if !evaluation.NextChangeAt.IsZero() {
			status.NextChangeAt = evaluation.NextChangeAt.In(beijingLocation).Format(time.RFC3339)
		}
		result.Statuses = append(result.Statuses, status)
	}
	return result, nil
}

func (s *ProviderPoolService) GetAccountPoolScheduleStatusesForUser(userID, platform string) (*AccountPoolScheduleStatuses, error) {
	userService, err := NewProviderPoolServiceForUser(userID)
	if err != nil {
		return nil, err
	}
	return userService.GetAccountPoolScheduleStatuses(platform)
}

type accountPoolScheduleSubscriptionKey struct{ path, poolID string }

var accountPoolScheduleSubscriptions = struct {
	sync.Mutex
	subscribers map[accountPoolScheduleSubscriptionKey]map[chan struct{}]struct{}
}{subscribers: make(map[accountPoolScheduleSubscriptionKey]map[chan struct{}]struct{})}

func accountPoolScheduleSubscriptionPath(path string) string {
	if absolute, err := filepath.Abs(path); err == nil {
		return filepath.Clean(absolute)
	}
	return filepath.Clean(path)
}

// subscribeAccountPoolScheduleChanges follows successful saves and deletions
// for one pool file and pool ID. A buffered signal coalesces concurrent writes;
// the subscriber rereads the latest configuration when it receives one.
func subscribeAccountPoolScheduleChanges(userID, poolID string) (<-chan struct{}, func(), error) {
	poolID = strings.TrimSpace(poolID)
	if poolID == "" {
		return nil, nil, errors.New("池子 ID 不能为空")
	}
	service := NewProviderPoolService()
	if strings.TrimSpace(userID) != "" {
		var err error
		service, err = NewProviderPoolServiceForUser(userID)
		if err != nil {
			return nil, nil, err
		}
	}
	key := accountPoolScheduleSubscriptionKey{path: accountPoolScheduleSubscriptionPath(service.path), poolID: poolID}
	changes := make(chan struct{}, 1)
	accountPoolScheduleSubscriptions.Lock()
	if accountPoolScheduleSubscriptions.subscribers[key] == nil {
		accountPoolScheduleSubscriptions.subscribers[key] = make(map[chan struct{}]struct{})
	}
	accountPoolScheduleSubscriptions.subscribers[key][changes] = struct{}{}
	accountPoolScheduleSubscriptions.Unlock()
	var once sync.Once
	cancel := func() {
		once.Do(func() {
			accountPoolScheduleSubscriptions.Lock()
			defer accountPoolScheduleSubscriptions.Unlock()
			delete(accountPoolScheduleSubscriptions.subscribers[key], changes)
			if len(accountPoolScheduleSubscriptions.subscribers[key]) == 0 {
				delete(accountPoolScheduleSubscriptions.subscribers, key)
			}
		})
	}
	return changes, cancel, nil
}

func notifyAccountPoolScheduleChanges(path, poolID string) {
	key := accountPoolScheduleSubscriptionKey{path: accountPoolScheduleSubscriptionPath(path), poolID: poolID}
	accountPoolScheduleSubscriptions.Lock()
	defer accountPoolScheduleSubscriptions.Unlock()
	for changes := range accountPoolScheduleSubscriptions.subscribers[key] {
		select {
		case changes <- struct{}{}:
		default:
		}
	}
}
