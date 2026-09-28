package modeltrace

import "testing"

// TestResolveModelExact 精确命中最优先
func TestResolveModelExact(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	for _, model := range bank.ModelIDs() {
		got, ok := bank.ResolveModel(model)
		if !ok || got != model {
			t.Errorf("ResolveModel(%q) = (%q, %v), 期望精确命中", model, got, ok)
		}
	}
}

// TestResolveModelNormalization 容忍 vendor 前缀、大小写与明确不改变身份的后缀
func TestResolveModelNormalization(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	cases := []struct {
		raw      string
		expected string
	}{
		{"gpt-5.4", "gpt-5.4"},
		{"GPT-5.4", "gpt-5.4"},
		{" Gpt-5.4 ", "gpt-5.4"},
		{"openai/gpt-5.4", "gpt-5.4"},
		{"openrouter/openai/gpt-5.4", "gpt-5.4"},
		{"gpt-5.4-2026-01-31", "gpt-5.4"},
		{"gpt-5.4-20260131", "gpt-5.4"},
		{"gpt-5.4-2026", "gpt-5.4"},
		{"gpt-5.4-latest", "gpt-5.4"},
		{"openai/gpt-6-sol-2026-09-23", "gpt-6-sol"},
		{"GPT-6-LUNA", "gpt-6-luna"},
		{"claude-opus-5", "claude-opus-5"},
		{"anthropic/claude-opus-5", "claude-opus-5"},
		// 库内 ID 是候选的前缀扩展：唯一命中即接受
		{"claude-haiku-4-5", "claude-haiku-4-5-20251001"},
	}
	for _, c := range cases {
		got, ok := bank.ResolveModel(c.raw)
		if !ok || got != c.expected {
			t.Errorf("ResolveModel(%q) = (%q, %v), 期望 (%q, true)", c.raw, got, ok, c.expected)
		}
	}
}

// TestResolveModelRejectsLookalikes 关键回归：绝不允许把"看起来像"的另一个型号
// 归一化到库里已有的模型——那正好是偷换模型（降智）最难发现的情形。
func TestResolveModelRejectsLookalikes(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	rejected := []string{
		"gpt-5.4-mini", // 更弱的同族型号
		"gpt-5.4-nano",
		"gpt-5.4-pro",   // 更强的同族型号
		"gpt-5.6",       // 有 3 个候选，歧义
		"gpt-6",         // 有 3 个候选，歧义
		"gpt-6-terra",   // 上游尚无独立指纹，不能借用其他型号
		"claude-opus-4", // 有 3 个候选，歧义
		"gpt-4o",
		"deepseek-v3",
		"",
		"   ",
		"gpt-5.4-mini-2026-01-31", // 剥离日期后仍是 mini
	}
	for _, raw := range rejected {
		if got, ok := bank.ResolveModel(raw); ok {
			t.Errorf("ResolveModel(%q) 不应命中，却得到 %q", raw, got)
		}
	}
}

// TestResolveModelCoversWholeBank 归一化能力必须覆盖库内每个模型
func TestResolveModelCoversWholeBank(t *testing.T) {
	bank, err := LoadBank()
	if err != nil {
		t.Fatalf("加载指纹库失败: %v", err)
	}
	if len(bank.Models) == 0 {
		t.Fatal("指纹库为空")
	}
	for _, model := range bank.Models {
		if !bank.ContainsModel(model.ID) {
			t.Errorf("%s 应被 ContainsModel 命中", model.ID)
		}
		if _, ok := bank.ResolveModel(model.ID + "-latest"); !ok {
			t.Errorf("%s-latest 应能归一化", model.ID)
		}
	}
}
