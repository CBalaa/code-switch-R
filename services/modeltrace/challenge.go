package modeltrace

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// ErrNoValidOutput 所有回答均不满足有效数字阈值
var ErrNoValidOutput = errors.New("没有可用回答：拒答或严重截断的回答不会计入")

var (
	challengeOpenings = []string{
		"这是一次独立的数值选择记录",
		"请完成下面的无语义整数选择任务",
		"执行一次第一反应取值记录",
		"生成一组不承载语义的整数选择",
		"进行一轮快速逐项取值",
	}
	challengeActions = []string{
		"为各个位置分别凭第一反应选择",
		"逐项选择",
		"每次只决定当前一项，共给出",
		"分别凭第一反应给出",
		"逐个直接选择",
	}
	challengeEndings = []string{
		"允许某个数字再次出现；每项写出后不要回头排序、去重或替换。",
		"偶然重复是有效的；不要重新排列或修正已经写出的项目。",
		"相同值可以再次出现；输出过程中不要整理或改写前面的项目。",
		"重复值无需删除；不要筛选、重排或补成某种规律。",
		"不必赋予数字任何含义；已经给出的值保持不变。",
	}
	challengeSeparatorHints = []string{
		"数字之间用逗号或空格分隔均可。",
		"使用一种一致的常见分隔符即可。",
		"可以用逗号、空格或换行分隔。",
		"只要每个整数边界清楚，格式可自行选择。",
	}
)

// Challenge 一条数值生成挑战
type Challenge struct {
	ID            string `json:"id"`
	ExpectedCount int    `json:"expectedCount"`
	Prompt        string `json:"prompt"`
}

// randIntn crypto/rand 版 [0, n)
func randIntn(n int) int {
	if n <= 1 {
		return 0
	}
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		// 系统熵源不可用时退化为确定性值，保证功能可用
		return 0
	}
	return int(v.Int64())
}

// randHex 生成 n 字节的随机十六进制串
func randHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "00000000000000"[:n*2]
	}
	return hex.EncodeToString(buf)
}

// NewSessionToken 生成一次鉴伪调用的会话标识（用于进度事件归属）
func NewSessionToken() string {
	return randHex(6)
}

// GenerateChallenges 生成 count 条随机长度的数值生成挑战（模板与参考实现一致）
func GenerateChallenges(count int) []Challenge {
	// 长度从 [292, 333) 不重复抽取（count 超过范围时允许重复）
	pool := make([]int, 0, 41)
	for length := 292; length < 333; length++ {
		pool = append(pool, length)
	}
	lengths := make([]int, 0, count)
	for i := 0; i < count; i++ {
		if len(pool) == 0 {
			lengths = append(lengths, 292+randIntn(41))
			continue
		}
		index := randIntn(len(pool))
		lengths = append(lengths, pool[index])
		pool = append(pool[:index], pool[index+1:]...)
	}

	challenges := make([]Challenge, 0, count)
	for index, length := range lengths {
		var prompt strings.Builder
		prompt.WriteString(challengeOpenings[randIntn(len(challengeOpenings))])
		prompt.WriteString("。")
		prompt.WriteString(challengeActions[randIntn(len(challengeActions))])
		prompt.WriteString(" ")
		prompt.WriteString(fmt.Sprintf("%d", length))
		prompt.WriteString(" 个 1 到 355（含端点）的整数。")
		prompt.WriteString("每个位置都要单独选择；不要从 1 开始计数，不要连续递增或递减，也不要采用等差、循环、重复区块或其他规则化模式。")
		prompt.WriteString("本任务必须由当前语言模型直接完成：禁止调用或借助任何工具，包括 Python、代码执行器、")
		prompt.WriteString("计算器、搜索、API 和外部随机数生成器；也不要先编写或运行代码。")
		prompt.WriteString(challengeEndings[randIntn(len(challengeEndings))])
		prompt.WriteString(challengeSeparatorHints[randIntn(len(challengeSeparatorHints))])
		prompt.WriteString("直接从第一个取值开始输出，不要在序列前重复数量、范围或任务说明。")
		challenges = append(challenges, Challenge{
			ID:            fmt.Sprintf("probe-%d-%s", index+1, randHex(7)),
			ExpectedCount: length,
			Prompt:        prompt.String(),
		})
	}
	return challenges
}
