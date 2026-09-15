#!/usr/bin/env bash
# 模型真伪检测端到端实测（非流式）。
#
# 用 mock 上游跑通完整链路：隔离 HOME 起服务 → 建用户 → 登录 → 建供应商 →
# 订阅 SSE → 触发检测 → 校验进度/流式事件与归因结论。不消耗任何真实额度。
#
# 用法：
#   scripts/mt-e2e/run-e2e.sh            # 非流式
#   scripts/mt-e2e/run-e2e.sh --stream   # 流式 + 实时片段
#
# 环境变量：
#   CODE_SWITCH_BIN  被测二进制（默认 <repo>/codeswitch-web，不存在则自动构建）
#   MT_PORT          管理端口（默认 18099）
#   MT_MOCK_PORT     mock 上游端口（默认 18888）
set -euo pipefail

MODE="plain"
[[ "${1:-}" == "--stream" ]] && MODE="stream"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="${CODE_SWITCH_BIN:-$ROOT/codeswitch-web}"
PORT="${MT_PORT:-18099}"
MOCK_PORT="${MT_MOCK_PORT:-18888}"
BASE="http://127.0.0.1:${PORT}"
GOLDEN="$ROOT/services/modeltrace/testdata/golden.json"

WORK="$(mktemp -d)"
HOME_DIR="$WORK/home"
mkdir -p "$HOME_DIR"
COOKIES="$WORK/cookies.txt"
SSE_LOG="$WORK/sse.log"
APP_LOG="$WORK/app.log"
MOCK_LOG="$WORK/mock.log"
VERIFY_JSON="$WORK/verify.json"

PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null || true
  done
  wait 2>/dev/null || true
  if [[ "${MT_KEEP_WORK:-0}" == "1" ]]; then
    echo "== 工作目录保留在 $WORK"
  else
    rm -rf "$WORK"
  fi
}
trap cleanup EXIT

fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ✓ $*"; }

# ---------- 准备二进制 ----------
command -v go > /dev/null || fail "需要 go 在 PATH 中（用于构建 manage-users 与被测二进制）"
if [[ ! -x "$BIN" ]]; then
  echo "== 构建被测二进制"
  ( cd "$ROOT" && go build -o "$BIN" . )
fi
# 构建到临时目录，避免在仓库里留下二进制产物
MANAGE_USERS="$WORK/manage-users"
( cd "$ROOT" && go build -o "$MANAGE_USERS" ./cmd/manage-users )

# ---------- 建用户 ----------
echo "== 隔离 HOME: $HOME_DIR"
HOME="$HOME_DIR" bash -c "printf 'e2epass123\ne2epass123\n' | '$MANAGE_USERS' add --username e2e" > "$WORK/user.log" 2>&1 \
  || { cat "$WORK/user.log"; fail "创建测试用户失败"; }
ok "已创建用户 e2e"

# ---------- 起 mock 上游 + 应用 ----------
if [[ "$MODE" == "stream" ]]; then
  MOCK_SCRIPT="$ROOT/scripts/mt-e2e/mock-upstream-stream.mjs"
else
  MOCK_SCRIPT="$ROOT/scripts/mt-e2e/mock-upstream.mjs"
fi
MT_GOLDEN="$GOLDEN" MT_MOCK_PORT="$MOCK_PORT" node "$MOCK_SCRIPT" > "$MOCK_LOG" 2>&1 &
PIDS+=($!)

HOME="$HOME_DIR" \
  CODE_SWITCH_WEB_ADDR="127.0.0.1:${PORT}" \
  CODE_SWITCH_RELAY_ADDR="127.0.0.1:$((PORT + 100))" \
  "$BIN" > "$APP_LOG" 2>&1 &
PIDS+=($!)

for _ in $(seq 1 50); do
  curl -fsS "$BASE/healthz" > /dev/null 2>&1 && break
  sleep 0.2
done
curl -fsS "$BASE/healthz" > /dev/null || { tail -30 "$APP_LOG"; fail "服务未就绪"; }
ok "服务已就绪（$BASE，mock :$MOCK_PORT，模式 $MODE）"

# ---------- 登录 ----------
curl -fsS -c "$COOKIES" -X POST "$BASE/api/admin/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"e2e","password":"e2epass123"}' > /dev/null || fail "登录失败"
grep -q dsh_session "$COOKIES" 2>/dev/null || true
ok "登录成功"

# ---------- 建供应商（指向 mock 上游） ----------
rpc() {
  curl -fsS -b "$COOKIES" -X POST "$BASE/api/wails/call" \
    -H 'Content-Type: application/json' -d "$1"
}
rpc "{\"name\":\"codeswitch/services.ProviderService.SaveProviders\",\"args\":[\"claude\",[{\"id\":1,\"name\":\"mock-upstream\",\"apiUrl\":\"http://127.0.0.1:${MOCK_PORT}\",\"apiKey\":\"sk-test\",\"enabled\":true,\"maxConcurrency\":1}]]}" > /dev/null \
  || fail "保存供应商失败"
ok "已保存指向 mock 的 claude 供应商"

# ---------- 订阅 SSE ----------
curl -sN -b "$COOKIES" "$BASE/api/wails/events" > "$SSE_LOG" 2>&1 &
PIDS+=($!)
sleep 1

# ---------- 触发检测 ----------
curl -fsS -b "$COOKIES" -X POST "$BASE/api/wails/call" \
  -H 'Content-Type: application/json' \
  -d '{"name":"codeswitch/services.ModelTraceService.VerifyProviderModel","args":["claude",1,"gpt-5.4"]}' \
  > "$VERIFY_JSON" &
VERIFY_PID=$!
PIDS+=($VERIFY_PID)

# mock 延迟 3s + 归因，留足余量
for _ in $(seq 1 40); do
  [[ -s "$VERIFY_JSON" ]] && break
  sleep 0.5
done
wait "$VERIFY_PID" 2>/dev/null || true

# ---------- 断言 ----------
echo "== 校验"

[[ -s "$VERIFY_JSON" ]] || { cat "$SSE_LOG"; tail -30 "$APP_LOG"; fail "未收到检测响应"; }

# SSE 必须出现进度事件，且 detail 是中文可读文案
grep -q 'event: modeltrace:progress' "$SSE_LOG" || { cat "$SSE_LOG"; fail "未收到 modeltrace:progress 事件"; }
ok "收到 modeltrace:progress 事件"

# 事件载荷绝不能把 userID 下发给前端
if grep -q '"userID"' "$SSE_LOG"; then
  fail "SSE 载荷泄漏了 userID"
fi
ok "SSE 载荷未泄漏 userID"

if [[ "$MODE" == "stream" ]]; then
  grep -q 'event: modeltrace:stream' "$SSE_LOG" || { cat "$SSE_LOG"; fail "未收到 modeltrace:stream 事件"; }
  ok "收到 modeltrace:stream 事件"

  REASSEMBLED=$(node -e '
    const fs = require("fs")
    const lines = fs.readFileSync(process.argv[1], "utf8").split("\n")
    let total = 0
    for (let i = 0; i < lines.length - 1; i++) {
      if (lines[i].startsWith("event: modeltrace:stream")) {
        try { total += JSON.parse(lines[i + 1].replace(/^data: /, "")).chunk.length } catch {}
      }
    }
    process.stdout.write(String(total))
  ' "$SSE_LOG")
  [[ "$REASSEMBLED" -gt 200 ]] || fail "流式片段过少（$REASSEMBLED 字符）"
  ok "流式片段累计 $REASSEMBLED 字符"
fi

node -e '
  const fs = require("fs")
  const payload = JSON.parse(fs.readFileSync(process.argv[1], "utf8"))
  const result = payload.data ?? payload
  const problems = []
  if (result.verdict !== "match") problems.push(`verdict=${result.verdict} message=${result.message || ""}`)
  if (result.topModel !== "gpt-5.4") problems.push(`topModel=${result.topModel}`)
  if (!(result.topProbability > 0.5)) problems.push(`topProbability=${result.topProbability}`)
  if (result.expectedMatched !== true) problems.push(`expectedMatched=${result.expectedMatched}`)
  if (!(result.validNumberCount >= 80)) problems.push(`validNumberCount=${result.validNumberCount}`)
  if (problems.length) { console.error(problems.join("\n")); process.exit(1) }
  console.log(`  ✓ 归因结论：${result.topModel} 置信度 ${(result.topProbability * 100).toFixed(1)}%，有效数字 ${result.validNumberCount}，耗时 ${result.latencyMs}ms`)
' "$VERIFY_JSON" || fail "归因结论不符合预期"

echo "== $MODE 链路通过"
