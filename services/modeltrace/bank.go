// Package modeltrace 实现基于数字分布指纹的模型归因检测。
//
// 算法与指纹库移植自 ModelTrace (MIT License, https://github.com/xqy2006/ModelTrace)，
// 许可证全文见同目录 LICENSE。相对上游的改动：
//   - 上游为 Python / JavaScript 实现，本包为 Go 移植，解析/特征/打分逐位对齐；
//   - 指纹库以 unified_bank.json 形式通过 go:embed 内嵌，无运行时文件依赖；
//   - 新增 Bank.ResolveModel 模型名归一化（容忍日期后缀与 vendor 前缀）；
//   - 新增 testdata/golden.json 对拍基准，由上游参考实现生成。
package modeltrace

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

//go:embed unified_bank.json
var unifiedBankJSON []byte

const (
	ValueMin = 1
	ValueMax = 355
	// Dimension 数字值域维度
	Dimension = ValueMax - ValueMin + 1
	// Alpha 直方图平滑系数
	Alpha = 0.5
	// MinimumValidNumbers 单条回答可接受的最少有效数字数
	MinimumValidNumbers = 80
)

// BankModel 指纹库中的单个模型条目
type BankModel struct {
	ID               string `json:"id"`
	DisplayName      string `json:"display_name"`
	Family           string `json:"family"`
	FamilyName       string `json:"family_name"`
	ResponseCount    int    `json:"response_count"`
	ValidNumberCount int    `json:"valid_number_count"`
	Counts           []int  `json:"counts"`
}

// BankCalibration 单一查询数量对应的 softmax 校准参数
type BankCalibration struct {
	Beta       float64 `json:"beta"`
	CVAccuracy float64 `json:"cv_accuracy"`
}

// BankRobustPart robust 评分所需的统计量（Hellinger 与有序块各一份）
type BankRobustPart struct {
	FeatureMean          []float64     `json:"feature_mean"`
	FeatureScale         []float64     `json:"feature_scale"`
	NuisanceBasis        [][]float64   `json:"nuisance_basis"`
	Centroids            [][]float64   `json:"centroids"`
	EnvironmentCentroids [][][]float64 `json:"environment_centroids,omitempty"`
	Weight               float64       `json:"weight,omitempty"`
}

// bankFile unified_bank.json 的原始结构
type bankFile struct {
	RecommendedQueries int         `json:"recommended_queries"`
	Models             []BankModel `json:"models"`
	Robust             struct {
		ModelOrder    []string       `json:"model_order"`
		Hellinger     BankRobustPart `json:"hellinger"`
		OrderedBlocks BankRobustPart `json:"ordered_blocks"`
	} `json:"robust"`
	Calibration map[string]BankCalibration `json:"calibration"`
}

// Bank 解析后的指纹库
type Bank struct {
	Models      []BankModel
	ModelOrder  []string
	Hellinger   BankRobustPart
	Ordered     BankRobustPart
	Calibration map[string]BankCalibration

	modelIndex map[string]int
}

var (
	bankOnce sync.Once
	bankInst *Bank
	bankErr  error
)

// LoadBank 解析内置的统一指纹库（进程内单例）
func LoadBank() (*Bank, error) {
	bankOnce.Do(func() {
		var file bankFile
		if err := json.Unmarshal(unifiedBankJSON, &file); err != nil {
			bankErr = fmt.Errorf("解析指纹库失败: %w", err)
			return
		}
		if len(file.Models) == 0 {
			bankErr = fmt.Errorf("指纹库为空")
			return
		}
		bankInst = &Bank{
			Models:      file.Models,
			ModelOrder:  file.Robust.ModelOrder,
			Hellinger:   file.Robust.Hellinger,
			Ordered:     file.Robust.OrderedBlocks,
			Calibration: file.Calibration,
			modelIndex:  make(map[string]int, len(file.Models)),
		}
		for i, model := range file.Models {
			bankInst.modelIndex[model.ID] = i
		}
	})
	return bankInst, bankErr
}

// ModelIDs 返回指纹库覆盖的模型 ID 列表（保持库内顺序）
func (b *Bank) ModelIDs() []string {
	ids := make([]string, len(b.Models))
	for i, model := range b.Models {
		ids[i] = model.ID
	}
	return ids
}

// ContainsModel 判断模型是否在指纹库覆盖范围内
func (b *Bank) ContainsModel(modelID string) bool {
	_, ok := b.modelIndex[modelID]
	return ok
}

// bankModelSuffixPattern 可安全剥离的版本/日期后缀。
// 只剥离明确不改变模型身份的后缀：日期、latest/preview 等。
// 故意不剥离 -mini / -nano / -fast / -thinking 这类后缀——它们代表另一个
// （通常更弱的）模型，正是本功能要检出的"降智/偷换"场景，
// 剥离后会把偷换误判成身份一致。
var bankModelSuffixPattern = regexp.MustCompile(`(?i)(-(latest|preview|exp|stable|v[0-9]+|[0-9]{4}-[0-9]{2}-[0-9]{2}|[0-9]{8}|[0-9]{6}|[0-9]{4}))+$`)

// ResolveModel 把供应商实际使用的模型名归一化到指纹库中的模型 ID。
//
// 依次尝试：精确匹配 -> 去掉 vendor 前缀（openai/gpt-5.4）-> 去掉日期/版本后缀
// （gpt-5.4-2026-01-31）-> 唯一前缀匹配（claude-haiku-4-5 -> claude-haiku-4-5-20251001）。
// 大小写不敏感。任何一步出现多个候选即视为歧义，返回 false——宁可报"不在覆盖范围"，
// 也不能把不同的模型误判成同一个。
func (b *Bank) ResolveModel(raw string) (string, bool) {
	candidate := strings.TrimSpace(raw)
	if candidate == "" {
		return "", false
	}
	// vendor 前缀：只取最后一段路径（OpenRouter 风格的 vendor/model）
	if index := strings.LastIndex(candidate, "/"); index >= 0 && index+1 < len(candidate) {
		candidate = strings.TrimSpace(candidate[index+1:])
	}
	if candidate == "" {
		return "", false
	}

	variants := []string{candidate}
	if stripped := bankModelSuffixPattern.ReplaceAllString(candidate, ""); stripped != "" && stripped != candidate {
		variants = append(variants, stripped)
	}

	// 精确匹配（含大小写不敏感），要求唯一命中
	matched := ""
	for id := range b.modelIndex {
		for _, variant := range variants {
			if strings.EqualFold(id, variant) {
				if matched != "" && matched != id {
					return "", false
				}
				matched = id
			}
		}
	}
	if matched != "" {
		return matched, true
	}

	// 唯一前缀匹配：库内 ID 以 "<候选>-" 开头（claude-haiku-4-5 -> claude-haiku-4-5-20251001）。
	// 反向（候选以库内 ID 开头）刻意不做，否则 gpt-5.4-mini 会被当成 gpt-5.4。
	for id := range b.modelIndex {
		lowerID := strings.ToLower(id)
		for _, variant := range variants {
			if strings.HasPrefix(lowerID, strings.ToLower(variant)+"-") {
				if matched != "" && matched != id {
					return "", false
				}
				matched = id
			}
		}
	}
	if matched != "" {
		return matched, true
	}
	return "", false
}

// SupportedModels 返回指纹库覆盖的模型描述（供前端选择器使用）
type ModelOption struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Family      string `json:"family"`
	FamilyName  string `json:"familyName"`
}

func (b *Bank) SupportedModels() []ModelOption {
	options := make([]ModelOption, 0, len(b.Models))
	for _, model := range b.Models {
		options = append(options, ModelOption{
			ID:          model.ID,
			DisplayName: model.DisplayName,
			Family:      model.Family,
			FamilyName:  model.FamilyName,
		})
	}
	return options
}
