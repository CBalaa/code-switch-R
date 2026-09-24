package services

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Only wallet quota is exposed; account profile, email and access tokens are excluded.
type NewAPIAccount struct {
	Quota    *float64 `json:"quota,omitempty"`
	QuotaUSD *float64 `json:"quotaUSD,omitempty"`
}

// Raw quota units are retained even when a site conversion is available.
type NewAPIKey struct {
	Object             string          `json:"object"`
	Name               string          `json:"name"`
	Total              *float64        `json:"total_granted,omitempty"`
	Used               *float64        `json:"total_used,omitempty"`
	Remaining          *float64        `json:"total_available,omitempty"`
	Unlimited          *bool           `json:"unlimited_quota,omitempty"`
	ExpiresAt          *int64          `json:"expires_at,omitempty"`
	ModelLimitsEnabled *bool           `json:"model_limits_enabled,omitempty"`
	ModelLimits        map[string]bool `json:"model_limits,omitempty"`
	TotalUSD           *float64        `json:"totalUSD,omitempty"`
	UsedUSD            *float64        `json:"usedUSD,omitempty"`
	RemainingUSD       *float64        `json:"remainingUSD,omitempty"`
}
type NewAPISite struct {
	QuotaPerUnit float64 `json:"quota_per_unit"`
}
type NewAPIPrice struct {
	Model      string   `json:"model"`
	Group      string   `json:"group"`
	GroupRatio *float64 `json:"groupRatio,omitempty"`
	Mode       string   `json:"mode"` // tokens, request, complex
	Input      *float64 `json:"input,omitempty"`
	Output     *float64 `json:"output,omitempty"`
	CacheRead  *float64 `json:"cacheRead,omitempty"`
	CacheWrite *float64 `json:"cacheWrite,omitempty"`
	Request    *float64 `json:"request,omitempty"`
}
type NewAPIPricing struct {
	Rows []NewAPIPrice `json:"rows"`
}
type newAPIModelPrice struct {
	Model                string            `json:"model_name"`
	QuotaType            *int              `json:"quota_type"`
	ModelRatio           *float64          `json:"model_ratio"`
	ModelPrice           *float64          `json:"model_price"`
	CompletionRatio      *float64          `json:"completion_ratio"`
	CacheRatio           *float64          `json:"cache_ratio"`
	CreateCacheRatio     *float64          `json:"create_cache_ratio"`
	ImageRatio           *float64          `json:"image_ratio"`
	AudioRatio           *float64          `json:"audio_ratio"`
	AudioCompletionRatio *float64          `json:"audio_completion_ratio"`
	Groups               []string          `json:"enable_groups"`
	BillingMode          string            `json:"billing_mode"`
	BillingExpr          string            `json:"billing_expr"`
	Plugins              []json.RawMessage `json:"billing_plugin_variants"`
}

func (s *ProviderInfoService) queryNewAPI(cacheKey, base, key string, force bool, config *UpstreamInfoConfig) *ProviderInfoResult {
	var quota, site, prices, account providerInfoCache
	accountToken, userID := strings.TrimSpace(config.AccountToken), strings.TrimSpace(config.AccountUserID)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		if key == "" {
			quota.state.Status = "missing_key"
			return
		}
		quota = s.section(cacheKey+":usage", base+"/api/usage/token/", key, force, "newapi_key", "")
	}()
	// Public endpoints deliberately receive no credentials, even on the same host.
	go func() {
		defer wg.Done()
		site = s.section(cacheKey+":site", base+"/api/status", "", force, "newapi_site", "")
	}()
	go func() {
		defer wg.Done()
		prices = s.section(cacheKey+":pricing", base+"/api/pricing", "", force, "newapi_pricing", "")
	}()
	if accountToken != "" {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if strings.ContainsAny(accountToken, "\r\n") {
				account.state.Status = "auth"
				return
			}
			if userID != "" {
				id, err := strconv.ParseInt(userID, 10, 64)
				if err != nil || id <= 0 {
					account.state.Status = "invalid_user_id"
					return
				}
			}
			account = s.section(cacheKey+":account", base+"/api/user/self", accountToken, force, "newapi_account", userID)
		}()
	}
	wg.Wait()
	result := &ProviderInfoResult{Platform: "newapi", UsageState: quota.state, SiteState: site.state, PricingState: prices.state}
	if accountToken != "" {
		result.AccountState = &account.state
		if account.state.Status == "ready" && len(account.data) > 0 {
			_ = json.Unmarshal(account.data, &result.Account)
		}
	}
	if len(quota.data) > 0 {
		_ = json.Unmarshal(quota.data, &result.Key)
	}
	if len(site.data) > 0 {
		_ = json.Unmarshal(site.data, &result.Site)
	}
	if len(prices.data) > 0 {
		_ = json.Unmarshal(prices.data, &result.Pricing)
	}
	if result.Site != nil {
		convert := func(raw *float64) *float64 {
			if raw == nil {
				return nil
			}
			value := *raw / result.Site.QuotaPerUnit
			if math.IsInf(value, 0) || math.IsNaN(value) {
				return nil
			}
			return &value
		}
		if result.Key != nil {
			result.Key.TotalUSD = convert(result.Key.Total)
			result.Key.UsedUSD = convert(result.Key.Used)
			result.Key.RemainingUSD = convert(result.Key.Remaining)
		}
		if result.Account != nil {
			result.Account.QuotaUSD = convert(result.Account.Quota)
		}
	}
	return result
}

func decodeNewAPI(body []byte, kind string) (json.RawMessage, string) {
	var envelope struct {
		Code       *bool               `json:"code"`
		Success    *bool               `json:"success"`
		Data       json.RawMessage     `json:"data"`
		GroupRatio map[string]*float64 `json:"group_ratio"`
	}
	if json.Unmarshal(body, &envelope) != nil {
		return nil, "invalid_response"
	}
	success := envelope.Success
	if kind == "newapi_key" {
		success = envelope.Code
	}
	if success == nil {
		return nil, "invalid_response"
	}
	if !*success {
		if kind == "newapi_account" && newAPIRequiresUserID(body) {
			return nil, "requires_user_id"
		}
		return nil, "upstream_error"
	}
	if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
		return nil, "invalid_response"
	}
	var value any
	switch kind {
	case "newapi_key":
		var data NewAPIKey
		if json.Unmarshal(envelope.Data, &data) != nil || data.Object != "token_usage" || (data.Total == nil && data.Used == nil && data.Remaining == nil && data.Unlimited == nil) {
			return nil, "invalid_response"
		}
		// Derived fields must never be accepted from upstream.
		data.TotalUSD, data.UsedUSD, data.RemainingUSD = nil, nil, nil
		value = data
	case "newapi_account":
		var data NewAPIAccount
		if json.Unmarshal(envelope.Data, &data) != nil || data.Quota == nil {
			return nil, "invalid_response"
		}
		data.QuotaUSD = nil
		value = data
	case "newapi_site":
		var data NewAPISite
		if json.Unmarshal(envelope.Data, &data) != nil || data.QuotaPerUnit <= 0 {
			return nil, "invalid_response"
		}
		value = data
	case "newapi_pricing":
		var models []newAPIModelPrice
		if json.Unmarshal(envelope.Data, &models) != nil {
			return nil, "invalid_response"
		}
		rows := make([]NewAPIPrice, 0)
		for _, model := range models {
			if model.Model == "" {
				return nil, "invalid_response"
			}
			groups := model.Groups
			for _, g := range groups {
				if g == "all" {
					groups = nil
					for group := range envelope.GroupRatio {
						groups = append(groups, group)
					}
					sort.Strings(groups)
					break
				}
			}
			// Missing group metadata is shown as unknown, never treated as a 1x group.
			if len(groups) == 0 {
				groups = []string{""}
			}
			seen := map[string]bool{}
			for _, group := range groups {
				if seen[group] {
					continue
				}
				seen[group] = true
				row := NewAPIPrice{Model: model.Model, Group: group, GroupRatio: validRatio(envelope.GroupRatio[group]), Mode: "complex"}
				complex := model.BillingExpr != "" || len(model.Plugins) > 0 || (model.BillingMode != "" && model.BillingMode != "ratio") || model.ImageRatio != nil || model.AudioRatio != nil || model.AudioCompletionRatio != nil
				if !complex && model.QuotaType != nil {
					switch *model.QuotaType {
					case 0:
						row.Mode = "tokens"
						// New API web/src/features/pricing/lib/price.ts:
						// USD per million input tokens = model_ratio * 2 * group_ratio.
						// quota_per_unit is only used for the key quota, not model prices.
						two := 2.0
						row.Input = priceProduct(model.ModelRatio, &two, row.GroupRatio)
						row.Output = priceProduct(row.Input, model.CompletionRatio)
						row.CacheRead = priceProduct(row.Input, model.CacheRatio)
						row.CacheWrite = priceProduct(row.Input, model.CreateCacheRatio)
					case 1:
						row.Mode = "request"
						row.Request = priceProduct(model.ModelPrice, row.GroupRatio)
					}
				}
				rows = append(rows, row)
				// Bound expansion of model × group data as well as the HTTP response size.
				if len(rows) > 20000 {
					return nil, "invalid_response"
				}
			}
		}
		sort.SliceStable(rows, func(i, j int) bool {
			if rows[i].Model == rows[j].Model {
				return rows[i].Group < rows[j].Group
			}
			return rows[i].Model < rows[j].Model
		})
		value = NewAPIPricing{Rows: rows}
	default:
		return nil, "invalid_response"
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, "invalid_response"
	}
	return data, "ready"
}
func validRatio(value *float64) *float64 {
	if value == nil || *value < 0 || math.IsNaN(*value) || math.IsInf(*value, 0) {
		return nil
	}
	return value
}
func priceProduct(values ...*float64) *float64 {
	result := 1.0
	for _, value := range values {
		if validRatio(value) == nil {
			return nil
		}
		result *= *value
	}
	if math.IsInf(result, 0) || math.IsNaN(result) {
		return nil
	}
	return &result
}

func newAPIRequiresUserID(body []byte) bool {
	var data struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(body, &data) != nil {
		return false
	}
	message := strings.ToLower(data.Message)
	return strings.Contains(message, "new-api-user") && (strings.Contains(message, "not provided") || strings.Contains(message, "missing") || strings.Contains(message, "未提供") || strings.Contains(message, "缺少"))
}
