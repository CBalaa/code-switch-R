package modeltrace

import (
	"math"
	"regexp"
	"sort"
	"unicode"
)

// digitPattern 连续数字串
var digitPattern = regexp.MustCompile(`\d+`)

// ParseNumbers 从模型输出文本中提取最长的一段有效数字序列。
// 规则与参考实现一致：两个数字之间出现字母即切段；仅保留 1..355 的值。
func ParseNumbers(text string) []int {
	type span struct {
		start int
		end   int
	}
	var runs [][]int
	var current []int
	previousEnd := 0
	for _, match := range digitPattern.FindAllStringIndex(text, -1) {
		separator := text[previousEnd:match[0]]
		value := 0
		for _, c := range text[match[0]:match[1]] {
			value = value*10 + int(c-'0')
		}
		if len(current) > 0 && hasAlphabeticRune(separator) {
			runs = append(runs, current)
			current = nil
		}
		if value >= ValueMin && value <= ValueMax {
			current = append(current, value)
		}
		previousEnd = match[1]
	}
	if len(current) > 0 {
		runs = append(runs, current)
	}
	best := 0
	for i, run := range runs {
		if len(run) > len(runs[best]) {
			best = i
		}
	}
	if len(runs) == 0 {
		return nil
	}
	return runs[best]
}

// hasAlphabeticRune 判断分隔文本中是否含字母（Unicode 类别 L，与 \p{L} 等价）
func hasAlphabeticRune(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// CountNumbers 统计数字值域直方图
func CountNumbers(numbers []int) []int {
	counts := make([]int, Dimension)
	for _, number := range numbers {
		counts[number-ValueMin]++
	}
	return counts
}

// standardize z-score 标准化（总体方差）
func standardize(values []float64) []float64 {
	mean := 0.0
	for _, v := range values {
		mean += v
	}
	mean /= float64(len(values))
	variance := 0.0
	for _, v := range values {
		d := v - mean
		variance += d * d
	}
	variance /= float64(len(values))
	scale := math.Sqrt(variance)
	if scale < 1e-12 {
		scale = 1e-12
	}
	out := make([]float64, len(values))
	for i, v := range values {
		out[i] = (v - mean) / scale
	}
	return out
}

func dot(left, right []float64) float64 {
	sum := 0.0
	for i := range left {
		sum += left[i] * right[i]
	}
	return sum
}

func norm(values []float64) float64 {
	return math.Sqrt(dot(values, values))
}

// subtractBasis 投影掉 nuisance 子空间（基向量按序正交投影，与参考实现一致）
func subtractBasis(values []float64, basis [][]float64) []float64 {
	out := append([]float64(nil), values...)
	for _, vector := range basis {
		projection := dot(out, vector)
		for i := range out {
			out[i] -= projection * vector[i]
		}
	}
	return out
}

// HellingerFeature 355 维边缘分布特征（加 Alpha 平滑后 sqrt 归一）
func HellingerFeature(counts []int) []float64 {
	total := float64(Dimension) * Alpha
	for _, c := range counts {
		total += float64(c)
	}
	feature := make([]float64, Dimension)
	for i, c := range counts {
		feature[i] = math.Sqrt((float64(c) + Alpha) / total)
	}
	return feature
}

// OrderedBlockFeature 74 维有序块特征：4 个位置块 × 16 值域 bin + 末位数字分布
func OrderedBlockFeature(numbers []int) []float64 {
	feature := make([]float64, 0, 74)
	base := len(numbers) / 4
	remainder := len(numbers) % 4
	start := 0
	for block := 0; block < 4; block++ {
		size := base
		if block < remainder {
			size++
		}
		bins := make([]float64, 16)
		for i := range bins {
			bins[i] = 0.5
		}
		for _, value := range numbers[start : start+size] {
			index := int(math.Floor((float64(value-1) / 355) * 16))
			if index > 15 {
				index = 15
			}
			if index < 0 {
				index = 0
			}
			bins[index]++
		}
		start += size
		total := 0.0
		for _, b := range bins {
			total += b
		}
		for _, b := range bins {
			feature = append(feature, math.Sqrt(b/total))
		}
	}
	lastDigits := make([]float64, 10)
	for i := range lastDigits {
		lastDigits[i] = 0.5
	}
	for _, value := range numbers {
		lastDigits[value%10]++
	}
	lastTotal := 0.0
	for _, d := range lastDigits {
		lastTotal += d
	}
	for _, d := range lastDigits {
		feature = append(feature, math.Sqrt(d/lastTotal))
	}
	return feature
}

// robustScoreCounts Hellinger 路打分：标准化 -> 去 nuisance 投影 -> 单位化 -> 质心点积 -> z-score
func robustScoreCounts(counts []int, bank *Bank) []float64 {
	artifact := bank.Hellinger
	feature := HellingerFeature(counts)
	projected := make([]float64, Dimension)
	for i, v := range feature {
		projected[i] = (v - artifact.FeatureMean[i]) / artifact.FeatureScale[i]
	}
	projected = subtractBasis(projected, artifact.NuisanceBasis)
	n := norm(projected)
	if n < 1e-12 {
		n = 1e-12
	}
	scores := make([]float64, len(artifact.Centroids))
	for i, centroid := range artifact.Centroids {
		scores[i] = dot(projected, centroid) / n
	}
	return standardize(scores)
}

// orderedBlockScores 有序块路打分：环境模板最大值 + nuisance 质心，各半融合
func orderedBlockScores(numbers []int, bank *Bank) []float64 {
	artifact := bank.Ordered
	feature := OrderedBlockFeature(numbers)
	dim := len(feature)
	standardized := make([]float64, dim)
	for i, v := range feature {
		standardized[i] = (v - artifact.FeatureMean[i]) / artifact.FeatureScale[i]
	}
	unitNorm := norm(standardized)
	if unitNorm < 1e-12 {
		unitNorm = 1e-12
	}
	unit := make([]float64, dim)
	for i, v := range standardized {
		unit[i] = v / unitNorm
	}

	modelCount := len(artifact.Centroids)
	// 每个模型取跨环境最大匹配分（与参考实现 Math.max 一致；初始为首个环境的分数，
	// 不能用 0 初始化——负分会被错误地丢弃）
	templateScores := make([]float64, modelCount)
	for i := range templateScores {
		templateScores[i] = math.Inf(-1)
	}
	for _, envCentroids := range artifact.EnvironmentCentroids {
		for i, centroid := range envCentroids {
			if s := dot(unit, centroid); s > templateScores[i] {
				templateScores[i] = s
			}
		}
	}
	template := standardize(templateScores)

	projected := subtractBasis(standardized, artifact.NuisanceBasis)
	pNorm := norm(projected)
	if pNorm < 1e-12 {
		pNorm = 1e-12
	}
	nuisanceScores := make([]float64, modelCount)
	for i, centroid := range artifact.Centroids {
		nuisanceScores[i] = dot(projected, centroid) / pNorm
	}
	nuisance := standardize(nuisanceScores)

	fused := make([]float64, modelCount)
	for i := range fused {
		fused[i] = 0.5*template[i] + 0.5*nuisance[i]
	}
	return standardize(fused)
}

// robustScoreNumbers 单条回答的全量融合打分（0.75 Hellinger + 0.25 有序块）
func robustScoreNumbers(numbers []int, bank *Bank) []float64 {
	marginal := robustScoreCounts(CountNumbers(numbers), bank)
	ordered := orderedBlockScores(numbers, bank)
	weight := bank.Ordered.Weight
	if weight == 0 {
		return marginal
	}
	fused := make([]float64, len(marginal))
	for i := range fused {
		fused[i] = (1-weight)*marginal[i] + weight*ordered[i]
	}
	return fused
}

// softmax 数值稳定的 softmax
func softmax(values []float64) []float64 {
	maximum := values[0]
	for _, v := range values {
		if v > maximum {
			maximum = v
		}
	}
	weights := make([]float64, len(values))
	total := 0.0
	for i, v := range values {
		weights[i] = math.Exp(v - maximum)
		total += weights[i]
	}
	for i := range weights {
		weights[i] /= total
	}
	return weights
}

// jsSimilarity JS 散度相似度（展示用参考指标）
func jsSimilarity(left, right []int) float64 {
	leftTotal := 0
	for _, v := range left {
		leftTotal += v
	}
	rightTotal := float64(Dimension) * Alpha
	for _, v := range right {
		rightTotal += float64(v)
	}
	p := make([]float64, Dimension)
	q := make([]float64, Dimension)
	mid := make([]float64, Dimension)
	for i := 0; i < Dimension; i++ {
		p[i] = float64(left[i]) / float64(leftTotal)
		q[i] = (float64(right[i]) + Alpha) / rightTotal
		mid[i] = (p[i] + q[i]) / 2
	}
	divergence := func(values, middle []float64) float64 {
		sum := 0.0
		for i, v := range values {
			if v != 0 {
				sum += v * math.Log(v/middle[i])
			}
		}
		return sum
	}
	js := (divergence(p, mid) + divergence(q, mid)) / 2
	return 1 - math.Sqrt(js/math.Ln2)
}

// Output 单条待归因回答
type Output struct {
	Text          string `json:"text"`
	ExpectedCount int    `json:"expected_count"`
}

// ModelResult 单模型归因结果
type ModelResult struct {
	Model             string  `json:"model"`
	DisplayName       string  `json:"displayName"`
	Family            string  `json:"family"`
	FamilyName        string  `json:"familyName"`
	Probability       float64 `json:"probability"`
	ProfileSimilarity float64 `json:"profileSimilarity"`
	Score             float64 `json:"score"`
}

// Result 一组回答的归因结果
type Result struct {
	Prediction       string        `json:"prediction"`
	PredictionName   string        `json:"predictionName"`
	Probability      float64       `json:"probability"`
	UsedOutputs      int           `json:"usedOutputs"`
	Results          []ModelResult `json:"results"`
	ExpectedModel    string        `json:"expectedModel"`
	Match            bool          `json:"match"`
	TopModel         string        `json:"topModel"`
	ValidNumberCount int           `json:"validNumberCount"`
}

// Analyze 对一组回答做归因打分。outputs 至少一条有效回答。
// expectedModel 为用户声称要检测的模型；top-1 与其不一致时 Match=false。
func Analyze(outputs []Output, expectedModel string, bank *Bank) (*Result, error) {
	var valid [][]int
	var validCounts [][]int
	var validScores [][]float64
	for _, item := range outputs {
		numbers := ParseNumbers(item.Text)
		minimum := MinimumValidNumbers
		if item.ExpectedCount > 0 {
			if m := int(math.Ceil(float64(item.ExpectedCount) * 0.55)); m > minimum {
				minimum = m
			}
		}
		if len(numbers) < minimum {
			continue
		}
		valid = append(valid, numbers)
		validCounts = append(validCounts, CountNumbers(numbers))
		validScores = append(validScores, robustScoreNumbers(numbers, bank))
	}
	if len(valid) == 0 {
		return nil, ErrNoValidOutput
	}

	modelCount := len(bank.Models)
	combined := make([]float64, modelCount)
	for i := range combined {
		sum := 0.0
		for _, scores := range validScores {
			sum += scores[i]
		}
		combined[i] = sum / float64(len(validScores))
	}

	key := "1"
	if len(valid) >= 2 {
		if len(valid) >= 3 {
			key = "3"
		} else {
			key = "2"
		}
	}
	calibration, ok := bank.Calibration[key]
	if !ok {
		calibration = BankCalibration{Beta: 1}
	}
	scaled := make([]float64, modelCount)
	for i, v := range combined {
		scaled[i] = calibration.Beta * v
	}
	probabilities := softmax(scaled)

	pooled := make([]int, Dimension)
	for _, counts := range validCounts {
		for i, c := range counts {
			pooled[i] += c
		}
	}

	totalNumbers := 0
	for _, numbers := range valid {
		totalNumbers += len(numbers)
	}

	results := make([]ModelResult, modelCount)
	for i, model := range bank.Models {
		results[i] = ModelResult{
			Model:             model.ID,
			DisplayName:       model.DisplayName,
			Family:            model.Family,
			FamilyName:        model.FamilyName,
			Probability:       probabilities[i],
			ProfileSimilarity: jsSimilarity(pooled, model.Counts),
			Score:             combined[i],
		}
	}
	sort.SliceStable(results, func(a, b int) bool {
		return results[a].Probability > results[b].Probability
	})

	top := results[0]
	match := top.Model == expectedModel
	return &Result{
		Prediction:       top.Model,
		PredictionName:   top.DisplayName,
		Probability:      top.Probability,
		UsedOutputs:      len(valid),
		Results:          results,
		ExpectedModel:    expectedModel,
		Match:            match,
		TopModel:         top.Model,
		ValidNumberCount: totalNumbers,
	}, nil
}
