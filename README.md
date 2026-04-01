# Code Switch

> 用网页管理 Claude Code / Codex / Gemini CLI 的供应商、代理、MCP 和提示词

## 这是什么

**Code Switch** 现在是一个适合 Linux 服务器的 Web 管理界面 + 本地代理服务，不再依赖桌面窗口或显示器。

它解决的是这类问题：

- 你有多个 AI API 供应商，想统一配置和切换
- 某个供应商挂了，想自动降级到备用供应商
- 想统计请求量、Token、成本和日志
- 想集中管理 MCP、CLI 配置、自定义提示词

一句话总结：浏览器负责配置，后台进程负责代理，Claude Code / Codex / Gemini CLI 继续走本机代理完成请求转发。

## 当前运行方式

当前仓库已经改成 Web 模式，默认会启动两个监听地址：

| 组件 | 默认地址 | 作用 |
|------|----------|------|
| Web 管理界面 | `127.0.0.1:8080` | 浏览器访问的管理后台 |
| Provider Relay | `127.0.0.1:18100` | Claude Code / Codex / Gemini CLI 实际走的本机代理 |

数据默认写入：

- `~/.code-switch/app.db`
- `~/.code-switch/app.json`
- `~/.code-switch/claude-code.json`
- `~/.code-switch/codex.json`
- `~/.code-switch/codex-relay-keys.json`
- `~/.code-switch/mcp.json`
- `~/.code-switch/prompts.json`
- `~/.code-switch/proxy-state/`

注意：

- Web 管理界面可以通过 SSH 隧道或反向代理从远端浏览器访问
- `8080` 管理后台现在内置管理员账号密码登录
- `18100` 上的 Codex API 现在只接受后台生成的 relay key
- 代理服务当前仍固定监听 `127.0.0.1:18100`
- 也就是说，Claude Code / Codex / Gemini CLI 应该运行在同一台服务器上

## Ubuntu 部署

下面的步骤已按当前机器验证：

- 系统：Ubuntu 24.04.3 LTS
- 仓库路径示例：`/home/chh/gitprojects/code-switch-R`
- Node.js：`v24.14.0`
- npm：`11.9.0`
- Go 构建环境：conda 环境 `code-switch-go-build-cgo`，`go1.26.1`

### 1. 准备构建环境

如果你已经有这个 conda 环境，直接激活即可：

```bash
conda activate code-switch-go-build-cgo
```

如果还没有，按当前机器的方式创建：

```bash
conda create -y -n code-switch-go-build-cgo -c conda-forge \
  'go=1.26.1' \
  'gcc_linux-64' \
  'gxx_linux-64'
conda activate code-switch-go-build-cgo
```

当前机器的 Node.js / npm 是系统里现成的。如果你的机器没有 Node.js，先安装一个可用版本，建议 `node >= 20`。

### 2. 构建前端

```bash
cd /home/chh/gitprojects/code-switch-R/frontend
npm install
npm run build
```

构建结果会输出到 `frontend/dist`。后端启动后会直接托管这个目录。

### 3. 构建后端

```bash
cd /home/chh/gitprojects/code-switch-R
conda activate code-switch-go-build-cgo
go build -o codeswitch-web .
```

### 4. 启动服务

```bash
cd /home/chh/gitprojects/code-switch-R
./codeswitch-web
```

正常启动后会看到类似日志：

```text
web admin listening on http://127.0.0.1:8080
provider relay listening on http://127.0.0.1:18100
```

### 5. 验证服务

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

预期返回：

```json
{"ok":true}
```

浏览器访问：

- 本机访问：`http://127.0.0.1:8080`
- 远端服务器场景：先做 SSH 隧道，再在本地浏览器打开 `http://127.0.0.1:8080`

SSH 隧道示例：

```bash
ssh -L 8080:127.0.0.1:8080 -L 18100:127.0.0.1:18100 your-user@your-server
```

## 作为守护进程运行

下面给一个 Ubuntu `systemd` 例子。路径按当前机器写，换机器时改成你的实际路径。

创建 `/etc/systemd/system/codeswitch.service`：

```ini
[Unit]
Description=Code Switch Web Service
After=network.target

[Service]
Type=simple
User=chh
WorkingDirectory=/home/chh/gitprojects/code-switch-R
Environment=CODE_SWITCH_WEB_ADDR=127.0.0.1:8080
ExecStart=/home/chh/gitprojects/code-switch-R/codeswitch-web
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
```

加载并启动：

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now codeswitch
```

查看日志：

```bash
sudo journalctl -u codeswitch -f
```

更新程序后的常见流程：

```bash
cd /home/chh/gitprojects/code-switch-R
git pull
cd frontend && npm install && npm run build
cd ..
conda activate code-switch-go-build-cgo
go build -o codeswitch-web .
sudo systemctl restart codeswitch
```

## 远程访问和安全建议

默认配置下，Web 管理界面只监听 `127.0.0.1:8080`，这通常是最安全的默认值。

如果你要让其他机器访问这个管理界面，有两种常见方式：

1. 保持默认监听，只通过 SSH 隧道访问
2. 把管理界面挂到 Nginx / Caddy 反向代理后面，并补上 TLS / 访问控制

管理界面监听地址可以通过环境变量修改：

```bash
export CODE_SWITCH_WEB_ADDR=0.0.0.0:8080
```

静态文件目录也可以改：

```bash
export CODE_SWITCH_STATIC_DIR=/your/path/to/frontend/dist
```

重要说明：

- 当前应用已经内置 `8080` 管理员登录鉴权，但如果要对公网开放，仍建议放在反向代理后面并启用 TLS
- `18100` 是 CLI / API relay 端口，默认只监听 `127.0.0.1:18100`
- `18100` 不建议直接暴露到公网；远程调用更推荐使用 SSH 隧道
- Codex 相关接口现在必须使用后台生成的 relay key，不能再随便填任意密钥

## 如何使用

### 1. 本机上怎么开启服务

先构建前端，再构建并启动后端：

```bash
cd /home/chh/gitprojects/code-switch-R/frontend
npm install
npm run build

cd /home/chh/gitprojects/code-switch-R
go build -o codeswitch-web .
./codeswitch-web
```

启动后会同时提供：

- Web 管理后台：`http://127.0.0.1:8080`
- Provider Relay：`http://127.0.0.1:18100`

健康检查：

```bash
curl http://127.0.0.1:8080/healthz
```

### 2. 远程怎么用

当前版本里，`18100` 默认只监听远程机器自己的 `127.0.0.1`，所以远程最稳的方式是 SSH 隧道。

如果服务跑在远程服务器，而你想在自己电脑上使用：

```bash
ssh -L 8080:127.0.0.1:8080 -L 18100:127.0.0.1:18100 your-user@your-server
```

隧道建立后：

- 本地浏览器访问 `http://127.0.0.1:8080`
- 本地脚本 / 客户端访问 `http://127.0.0.1:18100`

例如在本地测试 Codex relay：

```bash
curl http://127.0.0.1:18100/v1/models \
  -H "Authorization: Bearer csk_xxx"
```

### 3. 网页端怎么用

第一次打开网页后台：

1. 浏览器打开 `http://127.0.0.1:8080`
2. 先创建管理员账号和密码
3. 创建成功后会自动登录

以后再次访问：

1. 打开 `http://127.0.0.1:8080`
2. 输入管理员账号密码登录

### 4. 在网页里配置供应商

进入主界面后：

1. 点击右上角 `+`
2. 填写供应商名称、API URL、API Key
3. 按需配置模型支持和模型映射
4. 保存

推荐至少配置两个供应商，这样自动降级才有意义。

### 5. 在网页里打开对应 CLI 的代理

在主界面分别可以给这些目标打开代理：

- Claude Code
- Codex
- Gemini CLI
- 自定义 CLI

打开代理后，Code Switch 会把对应 CLI 的配置改为走本机代理 `127.0.0.1:18100`。

如果后续要恢复原始直连配置，直接在页面里把对应代理关闭即可。

### 6. 生成 Codex relay key

如果你要把 `18100` 当作 Codex API 服务给脚本、客户端或远程隧道后的本地工具使用：

1. 打开 `设置`
2. 进入 `安全设置`
3. 点击 `生成 key`
4. 复制生成出来的 `csk_...` key

调用时可以放在这些头里：

- `Authorization: Bearer csk_xxx`
- `X-Code-Switch-Key: csk_xxx`
- `X-API-Key: csk_xxx`

示例：

```bash
curl http://127.0.0.1:18100/responses \
  -H "Authorization: Bearer csk_xxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5-codex","input":"hello"}'
```

如果你只是通过网页打开 Codex CLI 代理，程序会为本机 Codex 配置注入可用的 relay key，一般不需要手动再填一遍。

### 7. 重启 CLI

代理配置切换后，建议重启一次相关 CLI 进程，再发起新请求。

### 8. 在日志和统计页面确认生效

确认是否正常工作，最简单的方法是：

1. 在 Claude Code / Codex / Gemini CLI 里实际发起一次请求
2. 回到网页的日志页面查看是否出现新记录
3. 再看统计页里的请求量、Token 和成本是否增长

### 9. MCP、提示词和配置管理

网页里还可以继续做这些事情：

- 管理 MCP Server
- 管理自定义提示词
- 编辑 CLI 配置
- 做供应商测速
- 查看可用性检查和黑名单状态

## 工作原理

```text
浏览器
  ↓
Code Switch Web UI (:8080)
  ↓
Go 服务层 / 配置管理 / 日志 / 事件
  ↓
Provider Relay (:18100)
  ↓
实际 API 供应商
```

实际请求链路是这样的：

1. 你在网页里配置供应商和代理开关
2. Code Switch 修改本机 CLI 配置，让 Claude Code / Codex / Gemini CLI 指向本地代理
3. CLI 请求发到 `127.0.0.1:18100`
4. Relay 按优先级、模型映射和健康状态选择供应商
5. 成功时返回结果，失败时自动尝试下一个供应商

## Web 模式和原桌面版的区别

当前仓库已经不是“有托盘的桌面应用”形态，主要差异如下：

- 没有系统托盘常驻入口
- 没有桌面窗口和显示器依赖
- 自动启动入口在 Web 模式下不再作为主流程
- 更新操作会跳转到发布页，不做原生自动下载和重启
- 桌面原生通知默认不作为主要交互方式，页面事件和日志仍然可用

这正是它适合跑在 Linux 服务器上的原因。

## 界面预览

| 亮色主题 | 暗色主题 |
|---------|---------|
| ![亮色主界面](resources/images/code-switch.png) | ![暗色主界面](resources/images/code-swtich-dark.png) |
| ![日志亮色](resources/images/code-switch-logs.png) | ![日志暗色](resources/images/code-switch-logs-dark.png) |

## 常见问题

### 浏览器关掉后，代理还在吗？

只要 `codeswitch-web` 进程还在，代理就还在。浏览器只是管理界面，不是服务本体。

### 页面打不开，提示找不到前端资源

先确认你已经执行过：

```bash
cd frontend
npm install
npm run build
```

后端需要 `frontend/dist/index.html` 才能提供 Web UI。

### Claude Code / Codex / Gemini CLI 没走代理

按顺序检查：

1. 对应平台的代理开关是否已经打开
2. CLI 是否已经重启
3. `codeswitch-web` 进程是否还活着
4. `127.0.0.1:18100` 是否在监听
5. 供应商 API URL / API Key 是否正确

### 配置怎么备份

直接备份整个目录即可：

```bash
~/.code-switch/
```

## 开发说明

当前开发方式不再是 `wails3 task dev`。

前端构建：

```bash
cd frontend
npm install
npm run build
```

后端运行：

```bash
cd /home/chh/gitprojects/code-switch-R
conda activate code-switch-go-build-cgo
go run .
```

常用检查命令：

```bash
go build ./...
go test ./...
cd frontend && npm run build
```

## 技术栈

| 层级 | 技术 |
|------|------|
| 后端 | Go + Gin + SQLite |
| 前端 | Vue 3 + TypeScript + Vite |
| 通信 | HTTP RPC + SSE |
| 数据目录 | `~/.code-switch/` |

## 开源协议

MIT License

---

问题反馈：<https://github.com/Rogers-F/code-switch-R/issues>
