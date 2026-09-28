package modeltrace

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"testing"
)

// goldenFile 由上游 ModelTrace 的 JavaScript 参考评分器生成的对拍基准。
// 新增模型的数据来自 data/*_reference.jsonl 中的真实模型回答。
type goldenCase struct {
	Name          string    `json:"name"`
	ExpectedModel string    `json:"expected_model"`
	Outputs       []Output  `json:"outputs"`
	Prediction    string    `json:"prediction"`
	Probabilities []float64 `json:"probabilities"`
	Scores        []float64 `json:"scores"`
}

func loadGolden(t *testing.T) []goldenCase {
	t.Helper()
	path := filepath.Join("testdata", "golden.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		t.Skip("testdata/golden.json 不存在，跳过对拍")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("读取 golden 文件失败: %v", err)
	}
	var cases []goldenCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatalf("解析 golden 文件失败: %v", err)
	}
	return cases
}

func TestAnalyzeAgainstGolden(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	if len(bank.Models) != 16 {
		t.Fatalf("指纹库模型数 = %d, 期望 16", len(bank.Models))
	}

	for _, testCase := range loadGolden(t) {
		t.Run(testCase.Name, func(t *testing.T) {
			if len(testCase.Probabilities) != len(bank.ModelOrder) || len(testCase.Scores) != len(bank.ModelOrder) {
				t.Fatalf("golden 向量维度不匹配：概率 %d、分数 %d、模型 %d",
					len(testCase.Probabilities), len(testCase.Scores), len(bank.ModelOrder))
			}
			result, err := Analyze(testCase.Outputs, testCase.ExpectedModel, bank)
			if err != nil {
				t.Fatalf("Analyze 失败: %v", err)
			}
			if len(result.Results) != len(bank.ModelOrder) {
				t.Fatalf("结果模型数 = %d, 期望 %d", len(result.Results), len(bank.ModelOrder))
			}
			if result.Prediction != testCase.Prediction {
				t.Errorf("prediction = %s, 期望 %s", result.Prediction, testCase.Prediction)
			}
			if result.Match != (testCase.ExpectedModel == testCase.Prediction) {
				t.Errorf("match = %v 与期望不一致", result.Match)
			}
			byModel := map[string]ModelResult{}
			for _, item := range result.Results {
				byModel[item.Model] = item
			}
			for i, modelID := range bank.ModelOrder {
				got, ok := byModel[modelID]
				if !ok {
					t.Fatalf("结果缺少模型 %s", modelID)
				}
				if diff := math.Abs(got.Probability - testCase.Probabilities[i]); diff > 1e-9 {
					t.Errorf("model %s probability = %.12f, 期望 %.12f (diff %.2e)",
						modelID, got.Probability, testCase.Probabilities[i], diff)
				}
				if diff := math.Abs(got.Score - testCase.Scores[i]); diff > 1e-9 {
					t.Errorf("model %s score = %.12f, 期望 %.12f (diff %.2e)",
						modelID, got.Score, testCase.Scores[i], diff)
				}
			}
		})
	}
}

func TestParseNumbers(t *testing.T) {
	cases := []struct {
		text     string
		expected []int
	}{
		{"1, 2, 3", []int{1, 2, 3}},
		{"前缀说明 5 7 9", []int{5, 7, 9}},       // 字母分隔 -> 前缀 run 与主体 run，主体更长
		{"5 7 9 后缀 1 2", []int{5, 7, 9}},     // 最长 run
		{"0 356 12", []int{12}},              // 越界值丢弃
		{"400 500 no digits here", nil},      // 全部越界
		{"3.14 15 26", []int{3, 14, 15, 26}}, // 小数点非字母，不断 run（与参考实现一致）
	}
	for _, c := range cases {
		got := ParseNumbers(c.text)
		if len(got) != len(c.expected) {
			t.Errorf("ParseNumbers(%q) = %v, 期望 %v", c.text, got, c.expected)
			continue
		}
		for i := range got {
			if got[i] != c.expected[i] {
				t.Errorf("ParseNumbers(%q)[%d] = %d, 期望 %d", c.text, i, got[i], c.expected[i])
			}
		}
	}
}

func TestGenerateChallenges(t *testing.T) {
	challenges := GenerateChallenges(3)
	if len(challenges) != 3 {
		t.Fatalf("挑战数 = %d", len(challenges))
	}
	seen := map[int]bool{}
	for _, challenge := range challenges {
		if challenge.ExpectedCount < 292 || challenge.ExpectedCount > 332 {
			t.Errorf("expected_count = %d, 超出 [292, 332]", challenge.ExpectedCount)
		}
		if seen[challenge.ExpectedCount] {
			t.Errorf("expected_count = %d 重复", challenge.ExpectedCount)
		}
		seen[challenge.ExpectedCount] = true
		if challenge.Prompt == "" || challenge.ID == "" {
			t.Error("prompt 或 id 为空")
		}
	}
}

func TestBankContains(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	for _, id := range []string{"gpt-5.4", "gpt-6-astra", "gpt-6-sol", "gpt-6-luna", "claude-opus-4-8", "claude-opus-5-5", "claude-haiku-4-5-20251001"} {
		if !bank.ContainsModel(id) {
			t.Errorf("指纹库应包含 %s", id)
		}
	}
	for _, id := range []string{"gpt-4o", "gpt-6-terra", "gemini-2.5-pro", "claude-opus-4-5"} {
		if bank.ContainsModel(id) {
			t.Errorf("指纹库不应包含 %s", id)
		}
	}
}
