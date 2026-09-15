package services

import (
	_ "embed"
	"strings"
)

// codexDefaultInstructions 是 Codex CLI 发给 Responses API 的默认 instructions。
//
// 来源：本机安装的 @openai/codex（openai/codex，Apache-2.0）二进制里内嵌的
// 模型 base_instructions 原文，仅做原样搬运，未做改写。
//
// 用途：Responses 平台上的探测类请求（模型真伪检测的挑战、连通性测试）默认带上它，
// 让请求与真实 Codex 客户端一致。这不只是"像"，很多中转对请求体有最小长度门槛
// （例如 ISRC 的 key 明确拒绝少于 2000 input token 的请求，按请求体大小判定），
// 而挑战提示词本身只有几百 token，不带 instructions 会被直接 400。
//
//go:embed codex_default_instructions.txt
var codexDefaultInstructions string

// CodexDefaultInstructions 返回 Codex CLI 的默认 instructions（首尾已去空白）。
func CodexDefaultInstructions() string {
	return strings.TrimSpace(codexDefaultInstructions)
}
