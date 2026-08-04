# CodeRelay

[![CI](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml/badge.svg)](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml)

CodeRelay 是一个 Go 实现的单用户、API-only、无状态验证码解析服务。调用项目在每次请求中提交本次上游凭据；CodeRelay 临时完成取码并返回 JSON，不持久化或跨请求缓存 TOTP、Outlook、FlySMS 凭据、邮件或验证码。

仓库只保留 Go 服务、Go 测试和语言无关 golden fixtures；旧服务实现、依赖、构建脚本和测试已移除。

支持：

1. Base32 TOTP Secret 或 `otpauth://totp/...`；
2. `email----password----client_id----refresh_token` Outlook 凭据，显式支持 IMAP 或 Microsoft Graph 邮件访问；
3. `email---token---https://flysms.xyz/icloud/pickup#...` FlySMS 凭据。

生产域名：

```text
https://2fa.077.li
```

完整调用契约见 [`docs/API调用指南.md`](docs/API调用指南.md)，设计与验收状态见 [`docs/Go重写方案书-v1.0.md`](docs/Go重写方案书-v1.0.md) 和 [`docs/Go重写进度.md`](docs/Go重写进度.md)。

## 核心边界

```text
受控后端项目
    │ POST /api/v1/code
    │ Authorization: Bearer <CodeRelay API token>
    │ JSON body: request-scoped upstream credential
    ▼
CodeRelay Go
    ├─ TOTP：本地 RFC 6238
    ├─ Outlook：OAuth refresh + explicit IMAP/Graph readonly mailbox access
    └─ FlySMS：固定 HTTPS JSON API
    ▼
{"code":"123456"}
```

CodeRelay：

- 只监听显式 loopback 地址，公网入口必须由 Caddy 提供；
- 不把请求级 credential 写入配置、文件、数据库、日志、URL 或跨请求缓存；
- Outlook compatibility password 解析后立即丢弃；
- OAuth access/refresh token、IMAP session 和 Graph polling state 只属于当前请求；
- Microsoft refresh-token rotation 只通过 `credential_update` 交给调用方；
- Outlook IMAP 使用 readonly `INBOX` 和 partial `BODY.PEEK`；Graph 只使用固定 Inbox GET、preview 和 bounded MIME `$value`；
- Microsoft token、Graph、Outlook IMAP 和 FlySMS 上游地址均为服务端固定策略；
- 所有资源、正文、消息、MIME、连接、请求和 admission 状态都有硬上限。

“无状态”不表示 credential 从未进入内存：HTTPS 解密、解析和上游调用期间它必然短暂存在。保证的是不持久化、不记录、不跨请求保留，并对应用层可控副本进行 best-effort 清理。

## API

唯一取码端点：

```http
POST /api/v1/code
Authorization: Bearer <CODERELAY_API_TOKEN>
Content-Type: application/json
Accept: application/json
```

公开健康端点：

```text
GET /health/live
GET /health/ready
```

### TOTP

```json
{
  "type": "totp",
  "credential": "BASE32_SECRET",
  "min_ttl": 5
}
```

### Outlook

```json
{
  "type": "outlook",
  "mail_access": "graph",
  "credential": "email----password----client_id----refresh_token",
  "not_before": "2026-08-02T03:00:00Z",
  "wait_seconds": 30
}
```

### FlySMS

```json
{
  "type": "flysms",
  "credential": "email---token---https://flysms.xyz/icloud/pickup#email=...&key=...",
  "not_before": "2026-08-02T03:00:00Z",
  "wait_seconds": 30
}
```

成功响应只包含 code 和可选 rotation：

```json
{
  "code": "123456",
  "credential_update": {
    "refresh_token": "new_refresh_token"
  }
}
```

错误响应也可能带 `credential_update`。调用方必须先原子持久化最新 rotation，再处理成功或错误；不得记录整个响应。

## 并发、排队与限流

默认生产策略：

```text
active requests:             20
bounded FIFO queue:           4
queue wait:                   2s
25th request:                 immediate 503 SERVER_BUSY
shared key rate:             240/minute
shared key burst:             40
IP token bucket:             enabled
principal/key token bucket:  enabled
IP limiter state cap:        10,000
principal state cap:          1,000
inbound connection cap:        128
```

认证、IP/key 限流和 admission 都发生在 credential body decode 之前。未通过 admission 的请求不读取或 drain body，并关闭该连接。

调用方整体 timeout 至少使用 90 秒。`503 SERVER_BUSY` 只能做有限、带抖动的退避，禁止无限重试。

## 配置

```bash
install -m 600 config.example.toml config.toml
mkdir -p secrets
chmod 700 secrets
```

签发 API token：

```bash
./dist/coderelay generate-api-token \
  --hash-file secrets/api-project-a.sha256
```

明文 token 只显示一次，应立即导入调用项目 secret manager。CodeRelay 配置只保存 mode-0600 SHA-256 hash 文件路径。

校验配置：

```bash
./dist/coderelay validate-config --config config.toml
```

启动：

```bash
./dist/coderelay serve --config config.toml
```

默认只监听：

```text
127.0.0.1:8787
```

## 构建与供应链

支持 Go `1.25.12` 和 `1.26.5`，默认构建工具链为 `go1.26.5`。

```bash
./scripts/build.sh
./dist/coderelay --version
(cd dist && sha256sum -c coderelay.sha256)
file dist/coderelay
```

构建产物为 `CGO_ENABLED=0`、linux/amd64、trimpath、stripped 静态二进制。

生成 CycloneDX 1.6 SBOM：

```bash
./scripts/generate-sbom.sh
(cd dist && sha256sum -c coderelay.cdx.json.sha256)
```

SBOM 使用固定 `cyclonedx-gomod v1.10.0` 从最终二进制生成。

## Phase 5 验证

常规门禁：

```bash
GOTOOLCHAIN=go1.26.5 go test ./... -count=1
GOTOOLCHAIN=go1.26.5 go test -race ./... -count=1
go vet ./...
staticcheck ./...
govulncheck ./...
```

单核 CPU/heap pprof：

```bash
CODERELAY_PROFILE_TIME=10s ./scripts/profile-phase5.sh
```

credential-safe 60 分钟单核 soak：

```bash
./scripts/build.sh
go run ./cmd/phase5-soak \
  -binary dist/coderelay \
  -duration 60m \
  -output /tmp/coderelay-phase5-soak.json
```

soak 使用随机 CodeRelay API token 和确定性的合成 TOTP credentials，不使用真实上游 credential。它验证：

- 20-request paced bursts 和共享 key 240/minute 策略；
- HTTP 200、credential/result isolation 和 internal 500；
- `/proc` FD/socket/thread/RSS 基线、峰值及回落；
- SIGUSR1 runtime goroutine snapshot 前后差值；
- 合成 token、credential 和返回 code 的结构化日志扫描；
- SIGTERM graceful shutdown 和 clean exit；
- steady RSS `<256 MiB`、stress peak RSS `<512 MiB`。

## Outlook 安全诊断字段

Outlook 鉴权失败时，服务日志只写固定、非敏感的 `source_stage`，不写 OAuth body、token、email 或 credential：

```text
outlook_oauth_token    Microsoft token endpoint 拒绝 refresh 请求
outlook_oauth_scope    refresh token/app consent 未返回所需 IMAP scope
outlook_imap_auth      Outlook IMAP 拒绝 XOAUTH2 access token
outlook_graph_scope    Graph token 缺少所需 delegated scope
outlook_graph_identity Graph身份验证或credential email匹配失败
outlook_graph_list     Graph Inbox列表读取失败
outlook_graph_message  Graph MIME读取失败
```

可用响应中的 `request_id` 在 `journalctl` 中关联。日志还包含固定 `mail_access=imap|graph`，但不包含email、message ID或token。禁止为了诊断临时开启请求 body、OAuth/Graph body、IMAP debug writer 或 access log。

## 本地 runtime snapshot

服务进程收到 `SIGUSR1` 时，只写一条不含请求或 credential 的结构化事件：

```text
runtime_snapshot: goroutines, heap_bytes, heap_sys_bytes
```

它用于本机 soak 的前后泄漏对照。CodeRelay 不开放 HTTP pprof、debug、metrics 或管理端点；CPU/heap pprof 仅由合成测试进程离线生成。

## CLI

```text
coderelay serve
coderelay validate-config
coderelay generate-api-token
coderelay --version
```

## 安全调用示例

```bash
secret-manager-render-coderelay-json | curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 90 \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  https://2fa.077.li/api/v1/code
```

不得在命令行参数中内联真实 credential，也不得创建普通权限的明文 request 文件。日志只允许记录 HTTP 状态、公共 error code、request ID 和耗时。

## 当前部署门禁

Phase 5 已证明并发、性能、资源和安全边界；Phase 5.5 已完成IMAP/Graph双模式的本地与fake-upstream实现门禁。真实Graph/IMAP新鲜码HTTP 200、成功响应rotation、显式未读状态、Caddy/VPS canary和消费项目端到端仍需按部署验收执行。仓库已经是Go-only，但这不应被误解为这些真实外部门禁已自动通过。
