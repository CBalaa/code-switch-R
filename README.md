# Code Switch

> 用网页管理 Claude Code / Codex / Gemini CLI 的供应商、代理、MCP 和提示词。

## 概览

Code Switch 是适合 Linux 服务器运行的 Web 管理界面 + 本地代理服务。浏览器负责配置，后台进程负责转发，Claude Code / Codex / Gemini CLI 继续通过本机代理访问实际 API 供应商。

它主要解决：

- 多个 AI API 供应商统一配置和切换。
- 供应商失败时自动降级到备用供应商。
- 统计请求量、Token、成本和请求日志。
- 集中管理 MCP、CLI 配置、自定义提示词。

## 运行方式

默认会启动两个监听地址：

| 组件 | 默认地址 | 作用 |
|------|----------|------|
| Web 管理界面 | `127.0.0.1:8080` | 浏览器访问的管理后台 |
| Provider Relay | `127.0.0.1:18100` | CLI / API 客户端实际访问的本机代理 |

生产环境推荐：

- Web 管理界面和 Provider Relay 默认都只监听本机回环地址。
- Caddy / Nginx 对外提供 HTTPS，并反代到本机端口。
- 不直接把 `8080` 裸露到公网。

数据默认写入：

```text
~/.code-switch/
```

常见文件：

- `app.db`、`app.db-wal`、`app.db-shm`：SQLite 数据库和 WAL 文件。
- `users.json`：Web 管理后台用户和密码哈希。
- `claude-code.json`、`codex.json`、`openai-responses.json`、`openai-chat.json`：供应商配置。
- `codex-relay-keys.json`：Provider Relay 的访问 key。
- `provider-pools.json`：供应商池和降级配置。
- `mcp.json`、`prompts.json`：MCP 和提示词。
- `proxy-state/`：各 CLI 的代理开关状态。
- `favicons/`、`icons/`：界面图标缓存。

这个目录包含 API key、relay key、用户凭据哈希等敏感数据，应按私密数据处理。

### 号池代理配置

号池代理不提供任何默认 YAML。用户需要在号池界面上传 YAML；上传后的配置对所有用户可见，
但只有上传者可以删除。其他用户可以仅对自己隐藏某个配置，不会影响共享代理运行时或其他用户。

## 生产约定

执行远程部署前，必须由用户明确提供服务器名称和连接方法。连接方法可以是本机 SSH 配置里的别名，也可以是 `user@host`；如果需要非默认端口、私钥、跳板机或其他 SSH 参数，也必须由用户一并提供，不能根据历史环境自行猜测。

例如：

```bash
ssh <用户提供的 SSH 目标>
```

本文档只使用占位变量，不假设任何固定服务器名、SSH 别名、主机地址或域名。下面的值均应替换为用户为本次操作提供的实际信息：

```bash
REMOTE_SERVER_NAME="<用户提供的服务器名称>"
SSH_TARGET="<用户提供的 SSH 别名或 user@host>"
ADMIN_DOMAIN="<用户提供的 Web 管理域名>"
API_DOMAIN="<用户提供的 API 域名>"
LOCAL_REPO="$(pwd)"
REMOTE_DIR="~/apps/code-switch"
DATA_DIR="~/.code-switch"
SERVICE_NAME="codeswitch.service"
```

后续示例假设 `SSH_TARGET` 已包含在 `~/.ssh/config` 中，或可以直接被 `ssh` 和 `scp` 使用。若用户提供的是其他连接命令，应按用户给出的参数等价调整 `ssh` 和 `scp`，不要把连接细节写死到仓库。

远程本机端口：

- Web 管理界面：`127.0.0.1:8080`
- Provider Relay：`127.0.0.1:18100`

生产权限原则：

- 普通发布只上传构建产物到生产机的 `~/apps/code-switch`。
- 需要 `sudo` 的操作由服务器操作员手动执行。
- 自动化助手或发布脚本不得尝试 `sudo`、`sudo -n`、`systemctl restart`、`systemctl stop`、`systemctl start`。如果发布需要重启，只能在产物替换完成后停止操作，并把下方“操作员重启”命令发给有 sudo 权限的人执行。
- 不用 `kill` / `pkill` 绕过 systemd 管理生产服务。
- 修改 `/etc`、Caddy/Nginx、nftables、防火墙、systemd、apt 安装软件都属于系统级操作。

## 构建

已验证环境：

- Ubuntu 24.04.3 LTS
- Node.js `v24.14.0`
- npm `11.9.0`
- Go `go1.26.1`
- conda 环境 `code-switch-go-build-cgo`

准备 Go 构建环境：

```bash
conda activate code-switch-go-build-cgo
```

如果没有这个环境：

```bash
conda create -y -n code-switch-go-build-cgo -c conda-forge \
  'go=1.26.1' \
  'gcc_linux-64' \
  'gxx_linux-64'
conda activate code-switch-go-build-cgo
```

构建前端：

```bash
cd frontend
npm install
npm run build
cd ..
```

构建后端：

```bash
go test ./...
go build -o codeswitch-web .
```

本地临时运行：

```bash
CODE_SWITCH_WEB_ADDR=127.0.0.1:8080 ./codeswitch-web
```

健康检查：

```bash
curl -fsS http://127.0.0.1:8080/healthz
```

预期：

```json
{"ok":true}
```

## 首次部署

首次部署分两部分：

1. 本地构建并上传产物。
2. 服务器操作员配置 systemd、Caddy 和防火墙。

### 上传产物

```bash
REPO_DIR="$(pwd)"
ARTIFACT_DIR="$(pwd)/.deploy"
mkdir -p "$ARTIFACT_DIR"

cd "$REPO_DIR/frontend"
npm install
npm run build

cd "$REPO_DIR"
go test ./...
go build -o codeswitch-web .

STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_TARGET="<用户提供的 SSH 别名或 user@host>"
REMOTE_DIR="~/apps/code-switch"
FRONTEND_TGZ="$ARTIFACT_DIR/codeswitch-frontend-dist.$STAMP.tgz"

tar -C frontend -czf "$FRONTEND_TGZ" dist
ssh "$SSH_TARGET" "mkdir -p $REMOTE_DIR/frontend"
scp codeswitch-web "$SSH_TARGET:$REMOTE_DIR/codeswitch-web.new"
scp "$FRONTEND_TGZ" "$SSH_TARGET:$REMOTE_DIR/codeswitch-frontend-dist.$STAMP.tgz"

ssh "$SSH_TARGET" "
  set -e
  cd $REMOTE_DIR

  rm -rf frontend/dist.new
  mkdir -p frontend/dist.new
  tar -xzf codeswitch-frontend-dist.$STAMP.tgz -C frontend/dist.new --strip-components=1

  if [ -f codeswitch-web ]; then
    cp codeswitch-web codeswitch-web.bak.$STAMP
  fi
  if [ -d frontend/dist ]; then
    rm -rf frontend/dist.bak.$STAMP
    mv frontend/dist frontend/dist.bak.$STAMP
  fi

  mv frontend/dist.new frontend/dist
  mv codeswitch-web.new codeswitch-web
  chmod +x codeswitch-web
"
```

### systemd 服务

以下命令需要服务器操作员执行：

```bash
REMOTE_DIR="$HOME/apps/code-switch"

sudo mkdir -p "$REMOTE_DIR/frontend"
sudo chown -R "$USER:$USER" "$HOME/apps"

ADMIN_DOMAIN="<用户提供的 Web 管理域名>"
SETUP_TOKEN="$(openssl rand -hex 32)"
echo "CODE_SWITCH_SETUP_TOKEN=$SETUP_TOKEN"

sudo tee /etc/systemd/system/codeswitch.service >/dev/null <<EOF
[Unit]
Description=Code Switch Web Service
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$REMOTE_DIR
Environment=CODE_SWITCH_WEB_ADDR=127.0.0.1:8080
Environment=CODE_SWITCH_STATIC_DIR=$REMOTE_DIR/frontend/dist
Environment=CODE_SWITCH_PUBLIC_ORIGIN=https://$ADMIN_DOMAIN
Environment=CODE_SWITCH_TRUSTED_PROXIES=127.0.0.1/32,::1/128
Environment=CODE_SWITCH_SETUP_TOKEN=$SETUP_TOKEN
ExecStart=$REMOTE_DIR/codeswitch-web
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable codeswitch.service
```

保存输出的 `CODE_SWITCH_SETUP_TOKEN`。首次公网初始化管理员账号时需要它。

### Caddy 反向代理

以下命令需要服务器操作员执行：

```bash
sudo apt update
sudo apt install -y caddy

sudo cp /etc/caddy/Caddyfile /etc/caddy/Caddyfile.bak.$(date +%Y%m%d-%H%M%S) 2>/dev/null || true

ADMIN_DOMAIN="<用户提供的 Web 管理域名>"
API_DOMAIN="<用户提供的 API 域名>"

sudo tee /etc/caddy/Caddyfile >/dev/null <<EOF
$ADMIN_DOMAIN {
    encode zstd gzip
    reverse_proxy 127.0.0.1:8080
}

$API_DOMAIN {
    # Responses/Chat streaming uses SSE; leave event bytes uncompressed.
    reverse_proxy 127.0.0.1:18100 {
        flush_interval -1
    }
}
EOF

sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl enable --now caddy
sudo systemctl reload caddy
```

### Nginx 反向代理（SSE）

`/responses`、`/v1/responses` 和流式 `/chat/completions` 会持续返回 SSE。API 域名应单独反代到 Provider Relay 的本机端口，并保持长空闲窗口：

```nginx
server {
    listen 443 ssl http2;
    server_name <API_DOMAIN>;

    # ssl_certificate / ssl_certificate_key 由服务器部署配置提供。
    location / {
        proxy_pass http://127.0.0.1:18100;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header Connection "";

        proxy_buffering off;
        proxy_cache off;
        gzip off;

        proxy_connect_timeout 60s;
        proxy_send_timeout 3600s;
        proxy_read_timeout 3600s;
        send_timeout 3600s;
    }
}
```

保持 Nginx 默认的 chunked transfer 行为；不要配置 `chunked_transfer_encoding off`。Relay 会在 SSE 响应中设置 `X-Accel-Buffering: no`、`Cache-Control: no-cache, no-transform`，并在已开始输出后发送保活注释，避免静默流被中间代理提前关闭。

如果服务器使用 nftables 且默认 `policy drop`，需要放行 `80/443`。下面示例保留 SSH、HTTP、HTTPS、ICMP：

```bash
sudo cp /etc/nftables.conf /etc/nftables.conf.bak.$(date +%Y%m%d-%H%M%S)

sudo tee /etc/nftables.conf >/dev/null <<'EOF'
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
        chain input {
                type filter hook input priority filter; policy drop;
                iif "lo" accept
                ct state established,related accept
                ct state invalid drop
                ip protocol icmp accept
                ip6 nexthdr ipv6-icmp accept
                tcp dport { 22, 80, 443 } accept
        }

        chain forward {
                type filter hook forward priority filter; policy drop;
        }

        chain output {
                type filter hook output priority filter; policy accept;
        }
}
EOF

sudo nft -c -f /etc/nftables.conf
sudo nft -f /etc/nftables.conf
```

启动服务：

```bash
sudo systemctl start codeswitch.service
sudo systemctl status codeswitch.service --no-pager -l
```

## 发布

后端通过 `CODE_SWITCH_STATIC_DIR` 从磁盘读取前端构建产物，不会把 `frontend/dist` 打进二进制。

发布执行边界：

- 发布者可以构建、上传、解压、备份和替换 `~/apps/code-switch` 下的产物。
- 发布者可以做不需要 sudo 的检查，例如 `curl http://127.0.0.1:8080/healthz`、`curl http://127.0.0.1:18100/v1/models`、`systemctl is-active codeswitch.service`。
- 发布者不能尝试任何 sudo 操作，也不能尝试重启 systemd 服务。即使认为当前用户可能有免密 sudo，也必须停止并通知操作员手动执行。

发布类型：

- 只改前端：上传 `frontend/dist`，通常不需要重启。
- 改了 Go 后端、路由、数据结构、relay、服务逻辑：上传 `codeswitch-web` 和 `frontend/dist`，然后由操作员重启服务。
- 只改 `cmd/manage-users`：重新构建并上传用户管理脚本和二进制，不需要重启服务。

### 纯前端发布

```bash
REPO_DIR="$(pwd)"
ARTIFACT_DIR="$(pwd)/.deploy"
mkdir -p "$ARTIFACT_DIR"

cd "$REPO_DIR/frontend"
npm install
npm run build

STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_TARGET="<用户提供的 SSH 别名或 user@host>"
REMOTE_DIR="~/apps/code-switch"
FRONTEND_TGZ="$ARTIFACT_DIR/codeswitch-frontend-dist.$STAMP.tgz"

tar -C "$REPO_DIR/frontend" -czf "$FRONTEND_TGZ" dist
ssh "$SSH_TARGET" "mkdir -p $REMOTE_DIR/frontend"
scp "$FRONTEND_TGZ" "$SSH_TARGET:$REMOTE_DIR/codeswitch-frontend-dist.$STAMP.tgz"

ssh "$SSH_TARGET" "
  set -e
  cd $REMOTE_DIR

  rm -rf frontend/dist.new
  mkdir -p frontend/dist.new
  tar -xzf codeswitch-frontend-dist.$STAMP.tgz -C frontend/dist.new --strip-components=1

  if [ -d frontend/dist ]; then
    rm -rf frontend/dist.bak.$STAMP
    mv frontend/dist frontend/dist.bak.$STAMP
  fi

  mv frontend/dist.new frontend/dist
"
```

### 后端或全量发布

```bash
REPO_DIR="$(pwd)"
ARTIFACT_DIR="$(pwd)/.deploy"
mkdir -p "$ARTIFACT_DIR"

cd "$REPO_DIR/frontend"
npm install
npm run build

cd "$REPO_DIR"
go test ./...
go build -o codeswitch-web .

STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_TARGET="<用户提供的 SSH 别名或 user@host>"
REMOTE_DIR="~/apps/code-switch"
FRONTEND_TGZ="$ARTIFACT_DIR/codeswitch-frontend-dist.$STAMP.tgz"

tar -C frontend -czf "$FRONTEND_TGZ" dist
ssh "$SSH_TARGET" "mkdir -p $REMOTE_DIR/frontend"
scp codeswitch-web "$SSH_TARGET:$REMOTE_DIR/codeswitch-web.new"
scp "$FRONTEND_TGZ" "$SSH_TARGET:$REMOTE_DIR/codeswitch-frontend-dist.$STAMP.tgz"

ssh "$SSH_TARGET" "
  set -e
  cd $REMOTE_DIR

  rm -rf frontend/dist.new
  mkdir -p frontend/dist.new
  tar -xzf codeswitch-frontend-dist.$STAMP.tgz -C frontend/dist.new --strip-components=1

  if [ -f codeswitch-web ]; then
    cp codeswitch-web codeswitch-web.bak.$STAMP
  fi
  if [ -d frontend/dist ]; then
    rm -rf frontend/dist.bak.$STAMP
    mv frontend/dist frontend/dist.bak.$STAMP
  fi

  mv frontend/dist.new frontend/dist
  mv codeswitch-web.new codeswitch-web
  chmod +x codeswitch-web
"
```

到这里自动发布必须停止。发布者需要把本次 `STAMP` 一并发给服务器操作员。

后端版本首次引入 `request_log` 查询索引和 30 分钟统计汇总时，不能让服务启动过程隐式扫描历史表。新二进制在发现“非空旧表缺少索引”或“统计汇总尚未回填”时会停止启动，并明确提示运行显式维护命令：

```bash
./codeswitch-web migrate-request-log-indexes
```

这个命令不是每次发布的固定步骤。只有满足以下任一条件时才执行：

- 新二进制启动失败，日志明确包含 `request_log index migration required`、`request_log usage rollup is not ready`，并提示运行 `migrate-request-log-indexes`。
- 对尚未完成该迁移的非空旧数据库，发布说明或服务器操作员明确要求提前安排维护迁移。

以下情况不需要执行：

- 新二进制重启后服务正常为 `active`，且 `/healthz` 返回成功。
- 数据库已经完成过该迁移，本次发布没有引入新的数据库迁移要求。
- 仅发布前端或其他不涉及该数据库结构的内容。

正常的后端发布应先由服务器操作员重启并检查服务；只有出现上述明确迁移提示时，才进入后面的维护流程。不要因为命令是幂等的就把它作为例行发布步骤重复运行。

该命令会逐个、幂等地创建缺失索引，并重新生成北京时间当天的 48 个 30 分钟统计桶后标记汇总可用。创建索引可能读取完整 `request_log`，当天汇总回填会读取当天记录；两者都可能增加数据库、WAL 或临时文件占用，因此必须安排维护窗口。迁移前应确认具备可回滚条件，并检查数据库大小和可用磁盘：

```bash
du -sh "$HOME/.code-switch/app.db" "$HOME/.code-switch/app.db-wal" 2>/dev/null || true
df -h "$HOME/.code-switch"
```

迁移命令采用 fail-closed 校验：它会先打印目标 `app.db` 的绝对路径和字节数，只以 `mode=rw` 打开既有数据库，并要求 `request_log` 已存在且至少有一条记录。目标数据库不存在、不是普通文件、缺少 `request_log` 或表为空时，命令会非零退出，不会创建配置目录、数据库、索引或统计汇总。执行前必须核对打印路径确实是生产数据库。新库或空库会在正常启动时只创建空汇总结构和 trigger，并自动标记可用，不会扫描 `request_log`。

流量统计字段和 `traffic_daily`、`traffic_metadata` 两张小表由服务正常启动时自动创建，不需要执行 `migrate-request-log-indexes`。新增 `request_log` 字段使用 SQLite 的 `ALTER TABLE ... ADD COLUMN`，不会扫描历史请求行。API 客户端、每次上游尝试和管理端请求结束后，只有能够明确归类为公网且能够关联到用户的正文流量才会累加到北京时间当天的统计行；本地回环、无法判断网络范围或无法关联用户的事件不会进入日志页统计。日志页分别展示 API 客户端、上游供应商、重试额外和管理端正文的入站/出站累计值，查询只按主键读取当前用户当天的少量聚合行，不回扫 `request_log` 或流量明细。旧版本若已创建 `traffic_event`，升级后的首次启动只接续当天可归因的公网正文并写入迁移标记，之后启动不会再扫描或写入该明细表；旧的网卡统计表会保留但不再读写。正文统计位于反向代理压缩前，不包含 HTTP/TLS 开销，默认保留 30 天。

确认满足迁移执行条件后，下面命令由服务器操作员手动执行。发布者只有在看到明确迁移提示时才需要通知操作员执行。迁移命令必须由 systemd 配置中的服务用户直接运行，不能加 `sudo`，否则会解析到错误的 HOME/数据库路径：

```bash
sudo systemctl stop codeswitch.service
"$HOME/apps/code-switch/codeswitch-web" migrate-request-log-indexes
sudo systemctl start codeswitch.service
sudo systemctl status codeswitch.service --no-pager -l
curl -fsS http://127.0.0.1:8080/healthz
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:18100/v1/models
```

如果迁移失败，保持服务停止，先检查错误和磁盘空间；已经成功创建的索引会保留，当天统计汇总只会在事务完整提交后标记可用，排除问题后可直接重跑同一命令。不要在服务在线时运行迁移。

预期：

- `healthz` 返回 `{"ok":true}`。
- 未带 relay key 请求 `127.0.0.1:18100` 返回 `401`。

如果重启后异常，由操作员执行回滚：

```bash
STAMP="<本次发布时间戳，例如 20260706-205801>"
cd ~/apps/code-switch
cp codeswitch-web.bak.$STAMP codeswitch-web
rm -rf frontend/dist
mv frontend/dist.bak.$STAMP frontend/dist
chmod +x codeswitch-web
sudo systemctl restart codeswitch.service
sudo systemctl status codeswitch.service --no-pager -l
```

### 发布管理用户脚本

```bash
REPO_DIR="$(pwd)"
ARTIFACT_DIR="$(pwd)/.deploy"
mkdir -p "$ARTIFACT_DIR"

STAMP="$(date +%Y%m%d-%H%M%S)"
SSH_TARGET="<用户提供的 SSH 别名或 user@host>"
REMOTE_DIR="~/apps/code-switch"
MANAGE_USERS_ARTIFACT="$ARTIFACT_DIR/manage-users.$STAMP"

go build -o "$MANAGE_USERS_ARTIFACT" ./cmd/manage-users
ssh "$SSH_TARGET" "mkdir -p $REMOTE_DIR/scripts"
scp "$MANAGE_USERS_ARTIFACT" "$SSH_TARGET:$REMOTE_DIR/scripts/manage-users.new"

ssh "$SSH_TARGET" "
  set -e
  cd $REMOTE_DIR

  if [ -f scripts/manage-users ]; then
    cp scripts/manage-users scripts/manage-users.bak.$STAMP
  fi
  mv scripts/manage-users.new scripts/manage-users
  chmod +x scripts/manage-users
"
```

使用：

```bash
cd ~/apps/code-switch
scripts/manage-users list
scripts/manage-users add --username <name>
scripts/manage-users reset-password --username <name>
scripts/manage-users disable --username <name>
scripts/manage-users enable --username <name>
```

## 验证

在服务器本机验证：

```bash
ss -ltnp | grep -E ':(8080|18100) '
curl -fsS http://127.0.0.1:8080/healthz
curl -i -sS -X POST http://127.0.0.1:18100/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{}'
curl -i -sS -X POST http://127.0.0.1:18100/responses \
  -H 'Content-Type: application/json' \
  -d '{}'
```

预期：

- `8080` 和 `18100` 都有监听。
- `healthz` 返回 `{"ok":true}`。
- 未带 relay key 的 API 请求返回 `401`。
- `/chat/completions` 和 `/responses` 不应返回 `404`。

公网验证：

```bash
ADMIN_DOMAIN="<用户提供的 Web 管理域名>"
API_DOMAIN="<用户提供的 API 域名>"

curl -fsS "https://$ADMIN_DOMAIN/healthz"
curl -i -sS -X POST "https://$API_DOMAIN/chat/completions" \
  -H 'Content-Type: application/json' \
  -d '{}'
```


## 使用

首次打开后台：

1. 浏览器打开生产环境 Web 管理域名。
2. 创建管理员账号和密码。
3. 如果是首次公网初始化，输入启动日志或 systemd 配置里的 setup token。
4. 登录后配置供应商。

配置供应商：

1. 点击右上角 `+`。
2. 填写供应商名称、API URL、API Key。
3. 按需配置模型支持、模型映射和供应商池。
4. 保存。

建议至少配置两个供应商，这样自动降级才有意义。

CLI 代理：

- 在主界面为 Claude Code、Codex/OpenAI Responses 或 OpenAI Chat 配置代理。
- 程序会把对应 CLI 配置指向 `127.0.0.1:18100`。
- 关闭代理会恢复原始直连配置。

生成 relay key：

1. 打开 `设置`。
2. 进入 `安全设置`。
3. 点击 `生成 key`。
4. 复制生成出来的 `csk_...` key。

调用示例：

```bash
curl http://127.0.0.1:18100/responses \
  -H "Authorization: Bearer csk_xxx" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-5-codex","input":"hello"}'
```

## 故障排查

服务状态：

```bash
sudo systemctl status codeswitch.service --no-pager -l
sudo journalctl -u codeswitch.service -n 160 --no-pager
```

端口监听：

```bash
ss -ltnp | grep -E ':(8080|18100|80|443) '
```

Caddy 状态：

```bash
sudo systemctl status caddy --no-pager -l
sudo journalctl -u caddy -n 120 --no-pager
```

HTTPS 证书申请失败时，优先检查：

- 域名是否解析到当前服务器公网 IP。
- 服务器防火墙是否放行 `80/443`。
- 云厂商安全组或网络 ACL 是否放行 `80/443`。
- Caddyfile 是否包含正确域名。

如果公网 `80/443` 超时而 SSH 正常，常见原因是 nftables 或云防火墙未放行端口。

## 开发

当前开发方式不再是 `wails3 task dev`。

前端：

```bash
cd frontend
npm install
npm run build
```

后端：

```bash
conda activate code-switch-go-build-cgo
go run .
```

常用检查：

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
