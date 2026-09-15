#!/usr/bin/env bash
# 模型真伪检测流式链路实测：mock 流式上游 + 真实二进制 + SSE 订阅，
# 校验"实时生成片段"（modeltrace:stream）能完整重组出模型回答。
# 逻辑与非流式脚本共用，见 run-e2e.sh。
set -euo pipefail
exec "$(dirname "${BASH_SOURCE[0]}")/run-e2e.sh" --stream
