# CodeRelay Go 重写方案书（v1.0）

> 文档状态：设计完成，尚未开始 Go 实现
> 目标版本：CodeRelay Go 1.0.0
> 生产域名：`https://2fa.077.li`
> 目标机器：Linux，1 vCPU，2 GiB RAM
> 硬性容量目标：同一个 CodeRelay API Key 下稳定处理 20 个并发取码请求

---

## 1. 执行摘要

CodeRelay 将从 Python/FastAPI/PyInstaller 重写为 Go 原生单二进制服务。重写保持当前 0.3 API 契约和无状态边界，不要求调用项目修改 credential 格式。

核心目标不是单纯“把 Python 翻译成 Go”，而是吸收现有实现暴露出的工程问题，建立一个有明确资源上限、超载行为、取消语义和验收指标的系统：

```text
两个调用项目
→ 共用一个 CodeRelay Bearer Token
→ 合计最多 20 个并发 POST /api/v1/code
→ CodeRelay 在 1 vCPU / 2 GiB VPS 上稳定处理
```

重写后的关键设计：

1. 使用 Go 1.26.x 和标准库 `net/http`；
2. HTTP Handler、Provider、IMAP 连接均以 `context.Context` 为生命周期边界；
3. 全局最多 20 个 active 请求，额外最多 4 个短队列请求；
4. admission 在读取 JSON body 前完成，超载时不解析 credential；
5. Microsoft/FlySMS 复用无 Cookie 的 HTTP 连接池；
6. Outlook 使用 goroutine + Go 网络轮询，不使用 Python 式工作线程池；
7. Outlook 使用readonly Select的邮件总数 + 单次批量、流式 sequence FETCH，响应中保留UID作为稳定标识；
8. 不跨请求保存 credential、access token、refresh token、邮件或验证码；
9. TOTP 采用纯标准库实现，无网络和第三方 TOTP 依赖；
10. 所有内存、响应体、邮件体、正则、队列、连接和 goroutine 均有上限；
11. 超载明确返回 `503 SERVER_BUSY`，不无限排队；
12. 以单核压测、race、fuzz、故障注入和真实 Provider 测试作为发布门禁。

Go 可以显著降低本地运行时开销并改善取消、连接池和并发模型，但不能消除 FlySMS/Microsoft 自身的延迟。本方案把上游问题转化为可预测的 timeout/error，而不是无限等待或内部资源失控。

本方案真正要回答的核心问题是：**在上游延迟不可控的前提下，如何证明CodeRelay自身不会因为第20个并发请求而发生排队放大、资源泄漏、身份状态串用或不可解释timeout？** 所有选型和门禁都围绕这个因果问题，而不是围绕“Go一定比Python快”的口号。

这里的20并发主要是20个I/O状态机，不是20个CPU核并行。`GOMAXPROCS=1`下，Go netpoll让等待socket的goroutine不占用一个OS线程；MIME/JSON等CPU工作则通过严格输入上限控制。

---

## 2. 需求与非目标

### 2.1 功能需求

唯一取码接口保持为：

```http
POST /api/v1/code
Authorization: Bearer <CODERELAY_API_TOKEN>
Content-Type: application/json
```

支持：

- `type=totp`：Base32 Secret 或 `otpauth://totp/...`；
- `type=outlook`：`email----password----client_id----refresh_token`；
- `type=flysms`：`email---token---canonical_pickup_url`。

普通成功响应：

```json
{"code":"123456"}
```

Outlook token 轮换：

```json
{
  "code": "123456",
  "credential_update": {
    "refresh_token": "NEW_REFRESH_TOKEN"
  }
}
```

错误响应也允许包含 `credential_update`。

### 2.2 性能与稳定性需求

- 同一个 CodeRelay API Key 可以被两个项目共用；
- 合计 20 个并发请求不发生 credential 串用；
- 20 个 active 请求不能因为本地线程池排队产生伪 timeout；
- 第 21 个以上请求受到明确背压；
- 请求取消后，HTTP、TLS、IMAP 连接和 goroutine 必须及时退出；
- 服务端不能无限创建 goroutine、连接、队列或缓冲区；
- 进程在 2 GiB VPS 上必须保留足够系统/Caddy余量；
- 单个慢上游不能阻塞其他请求的 Go 调度器；
- 关闭服务时完成有界 graceful shutdown。

### 2.3 安全需求

服务器只持久化：

- CodeRelay API Token 的 SHA-256 hash；
- 不含上游 credential 的 TOML 策略配置。

禁止持久化：

- TOTP Secret；
- Outlook password/client ID/refresh token/access token；
- FlySMS email/token/pickup URL；
- 邮件正文；
- 验证码。

credential 不得进入：

- URL；
- 普通日志；
- panic 文本；
- metrics label；
- tracing attribute；
- Git；
- core dump；
- pprof 公网接口。

### 2.4 明确非目标

用户已确认以下问题暂不纳入本轮：

- FlySMS 上游本身的长延迟无法由语言解决；
- 同一邮箱内多封验证码的业务关联无法仅靠运行时解决；
- 多用户权限系统；
- 数据库；
- Docker 部署；
- 网页 UI；
- 多实例分布式协调；
- 在 CodeRelay 内持久化上游 credential。

Go 1.0 首版仍采用：

```text
单 VPS
单进程
单实例
Caddy HTTPS 反向代理
```

---

## 3. 设计原则

### 3.1 有界优先于“尽量处理”

每个资源都有显式上限：

- active 请求：20；
- 短等待队列：4；
- admission 等待：2 秒；
- request body：128 KiB；
- API Header：16 KiB；
- Outlook 邮件数：10；
- 单封邮件 FETCH：256 KiB；
- FlySMS detail：5；
- 上游响应体：按端点设置；
- 正则数量和长度：固定上限；
- normalized text：100 KiB/邮件；
- shutdown：90 秒硬上限。

### 3.2 先背压，再读取 credential

中间件顺序必须为：

```text
Request ID
→ panic recovery
→ security headers
→ Host/Method/Content-Type
→ Bearer 鉴权
→ IP/Key 限流
→ admission control
→ MaxBytesReader
→ JSON 解析
→ credential validation
→ Provider
```

这样超过容量的请求在读取 JSON body 前就被拒绝，避免在内存中堆积 credential。

### 3.3 复用连接，不复用身份状态

允许跨请求复用：

- Microsoft/FlySMS 的 TCP/TLS 连接；
- 预编译正则；
- 不含敏感数据的 immutable config；
- 限流器和 admission 控制器。

禁止跨请求复用：

- Cookie；
- Authorization header；
- request body；
- Provider；
- OAuth access token；
- refresh token；
- IMAP connection；
- 邮件；
- 验证码。

### 3.4 取消必须向下传播

所有外部操作都从 Handler 的 `r.Context()` 派生：

```text
client disconnect / server shutdown / operation timeout
→ context canceled
→ HTTP request canceled
→ IMAP conn deadline/Close
→ fetch reader 退出
→ Provider 返回
→ admission slot 释放
```

### 3.5 测量后优化

禁止凭感觉引入：

- 无界 cache；
- 无界 goroutine；
- 无界 channel；
- 对敏感 buffer 使用未清零的 `sync.Pool`；
- 为“性能”关闭超时、验证或 body 限制。

性能优化必须由 benchmark/pprof/trace 数据支持。

### 3.6 优化优先级

按收益排序：

1. 减少上游网络往返（IMAP批量FETCH、请求内session复用）；
2. 复用安全的HTTP TCP/TLS Transport；
3. 在读取大对象前完成鉴权、限流和admission；
4. streaming + hard limits控制内存和CPU；
5. 正确取消避免幽灵工作；
6. 最后才根据benchmark减少小对象分配。

这避免花时间优化JSON纳秒级开销，却保留8～10次IMAP往返这种真正瓶颈。

---

## 4. 技术选型

### 4.1 Go 版本

- CI/构建工具链：Go 1.26.x 最新补丁版；
- `go.mod` language version：`go 1.25.0`，兼容 Go 当前支持窗口；
- 生产构建：`CGO_ENABLED=0`；
- 目标：Linux amd64，后续可直接交叉构建 arm64；
- 不依赖 glibc。

Go 1.26 在 2026-02 发布，默认启用新的 Green Tea GC。方案不依赖 1.26 专属语法，以便保持 1.25 语言兼容。

### 4.2 Web 层

使用标准库：

```text
net/http
http.ServeMux
encoding/json
log/slog
```

不采用 Gin、Fiber、Echo：

- 当前只有少量固定 API；
- 标准库已支持 method-aware routing；
- 减少反射、依赖、分配和供应链面积；
- 更容易精确控制 body、deadline、连接和中间件顺序。

### 4.3 配置

使用：

```text
github.com/pelletier/go-toml/v2 v2.4.3
```

原因：

- 保留现有 TOML 运维体验；
- 严格解析和 unknown-field rejection；
- 仅启动时使用，不在热路径。

### 4.4 IMAP/MIME

首选并固定：

```text
github.com/emersion/go-imap/v2 v2.0.0-beta.8
github.com/emersion/go-message v0.18.2
github.com/emersion/go-sasl（go-imap 固定的版本）
```

`go-imap/v2` 当前仍为 beta，因此必须：

1. 封装在 `internal/provider/outlook/imapAdapter` 后；
2. pin 精确 tag；
3. 提交 `go.sum`；
4. 建议 vendor 该依赖；
5. 禁止直接把库类型泄露到 domain/service；
6. Phase 0 先用真实 Outlook 完成风险门禁；
7. 只有门禁通过才进入主体重写。

如果 beta.8 在真实环境出现不可接受问题，回退顺序：

```text
A. 在内部 Adapter 中修补并 vendor 固定最小 fork
B. 评估稳定 v1.2.1 Adapter
C. 最后才考虑实现严格子集 IMAP client
```

不建议一开始自己实现完整 IMAP parser，因为 literals、tagged response、challenge 和错误恢复的正确性风险高于库的 beta 风险。

### 4.5 HTML 处理

使用：

```text
golang.org/x/net/html v0.57.0
```

采用 streaming tokenizer，只提取可见文本，跳过：

```text
script style head noscript svg template
```

### 4.6 Unicode 兼容

直接依赖并固定：

```text
golang.org/x/text v0.40.0
```

使用 `cases.Fold()` 对齐 Python `str.casefold()`，而不是简单 `strings.ToLower()`。email、sender、domain和keyword的长度按Unicode scalar/rune计数；是否接受某个边界输入必须由跨语言golden fixture决定。

### 4.7 TOTP

使用 Go 标准库自行实现 RFC 6238：

```text
encoding/base32
crypto/hmac
crypto/sha1
crypto/sha256
crypto/sha512
encoding/binary
net/url
```

不引入 TOTP 第三方依赖。实现范围小，RFC 测试向量明确。

---

## 5. 总体架构

```text
Caddy :443
   │ HTTPS
   ▼
CodeRelay Go :8787 loopback
   │
   ├─ Middleware Chain
   │    ├─ auth/rate/admission
   │    └─ JSON limits/security headers
   │
   ▼
Resolver.Resolve(ctx, Command)
   │ request-scoped
   ├─ TOTP Provider
   ├─ Outlook Provider
   │    ├─ shared Microsoft HTTP transport
   │    └─ request-scoped IMAP TLS connection
   └─ FlySMS Provider
        └─ shared FlySMS HTTP transport
```

跨请求存在的对象必须在架构图中可枚举：

```text
Config（无上游 credential）
API token hashes
Rate limit state
Admission channels
Microsoft http.Client/Transport（Jar=nil）
FlySMS http.Client/Transport（Jar=nil）
Precompiled extraction rules
Metrics counters（无敏感 label）
```

除此以外的上游状态均为请求级。

---

## 6. 推荐代码布局

```text
cmd/coderelay/main.go
internal/
  api/
    handler.go
    models.go
    errors.go
    middleware.go
  admission/
    controller.go
  auth/
    bearer.go
    ratelimit.go
  config/
    config.go
    validate.go
  credential/
    secret.go
    outlook.go
    flysms.go
  domain/
    command.go
    result.go
    errors.go
    message.go
  extractor/
    extractor.go
    html.go
    rules.go
  provider/
    provider.go
    totp/
      provider.go
      otpauth.go
    outlook/
      provider.go
      oauth.go
      imap.go
      xoauth2.go
      mime.go
    flysms/
      provider.go
      contract.go
  service/
    resolver.go
    polling.go
  observability/
    logging.go
    metrics.go
  runtimecfg/
    limits.go
testdata/
  extractor/
  mime/
  contracts/
scripts/
  build-go.sh
  loadtest.sh
```

关键接口只暴露 domain 类型：

```go
type Resolver interface {
    Resolve(ctx context.Context, cmd Command) (Result, error)
}

type Provider interface {
    Fetch(ctx context.Context, req FetchRequest) (ProviderResult, error)
    CredentialUpdate() *CredentialUpdate
    AttemptTimeout() time.Duration
    PollInterval() time.Duration
    Close() error // idempotent; never exposes secret in error
}

type Result struct {
    Code             string
    CredentialUpdate *CredentialUpdate
}

type DomainError struct {
    Code              ErrorCode
    HTTPStatus        int
    Retryable         bool
    RetryAfterSeconds int
    CredentialUpdate  *CredentialUpdate
    cause             error // internal only; never serialized
}
```

Provider 的第三方库类型不得越过 `internal/provider/...`。

---

## 7. API 契约

### 7.1 请求

TOTP：

```json
{
  "type": "totp",
  "credential": "BASE32_SECRET",
  "min_ttl": 5
}
```

Outlook：

```json
{
  "type": "outlook",
  "credential": "email----password----client_id----refresh_token",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

FlySMS：

```json
{
  "type": "flysms",
  "credential": "email---token---https://flysms.xyz/icloud/pickup#email=...&key=...",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

### 7.2 JSON 解析要求

- `Content-Type` 通过 `mime.ParseMediaType` 后必须是 `application/json`，仅允许可选 `charset=utf-8`；
- admission 成功后才调用 `http.MaxBytesReader(..., 128<<10)`；
- 将 bounded body 读取到请求级 `[]byte`，先用 `utf8.Valid` 拒绝非法 UTF-8；
- 第一阶段只识别根对象和 `type`，第二阶段按 type 解码为精确结构；
- 第二阶段使用 `json.Decoder.DisallowUnknownFields()`，从而拒绝把 `min_ttl` 传给邮件类型或把 `wait_seconds` 传给 TOTP；
- 拒绝重复 root key、非 object root、尾随 JSON value 和尾随非空白字符；
- body buffer、`json.RawMessage` 和 credential临时 byte slice必须在 defer 中 best-effort `clear`；
- `type` 必须是固定枚举；
- 不在 validation error 中返回 input、字段 value 或底层 JSON syntax上下文；
- credential长度按Unicode scalar二次校验：TOTP≤8,192，Outlook≤70,000，FlySMS≤4,096；
- `not_before` 使用 RFC3339Nano，必须包含 timezone，转为 UTC，最多允许未来 5 分钟；
- `wait_seconds` 请求字段范围保持 0～60、默认20，且不得超过 `server.max_wait_seconds`（生产默认30）；
- `min_ttl` 范围 0～30、默认5。

两阶段解码最多占用约 `20 × 128 KiB = 2.5 MiB`，换来严格的 discriminated-union 兼容性。拒绝重复 key 是对含义不明确请求的安全收紧。

### 7.3 成功响应

普通：

```json
{"code":"123456"}
```

轮换：

```json
{
  "code": "123456",
  "credential_update": {
    "refresh_token": "..."
  }
}
```

成功/错误对象先用`json.Marshal`形成bounded小响应，不用streaming encoder或共享pool；写完后clear包含code/refresh token的可写buffer。`credential_update.refresh_token`继续校验100～65,536 Unicode scalar且无whitespace。

### 7.4 错误响应

```json
{
  "error": {
    "code": "NO_FRESH_CODE",
    "message": "No matching fresh verification code was found",
    "retryable": true,
    "retry_after_seconds": 2,
    "request_id": "..."
  }
}
```

兼容并补充的错误表：

| HTTP | Code | Retryable |
|---:|---|---:|
| 401 | `AUTHENTICATION_REQUIRED` | false |
| 404 | `NO_FRESH_CODE` | true |
| 409 | `AMBIGUOUS_CODE` | false |
| 413 | `REQUEST_TOO_LARGE` | false |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | false |
| 422 | `VALIDATION_ERROR` / `INVALID_CODE_REQUEST` / `HTTP_ERROR` | false |
| 424 | `SOURCE_CREDENTIALS_INVALID` | false |
| 424 | `SOURCE_REAUTH_REQUIRED` | false |
| 424 | `SOURCE_EXPIRED_OR_DISABLED` | false |
| 429 | `RATE_LIMITED` / `SOURCE_RATE_LIMITED` | true |
| 502 | `UPSTREAM_FAILURE` | true |
| 502 | `UPSTREAM_SCHEMA_CHANGED` | false |
| 503 | `SOURCE_SYNCING` / `SERVER_BUSY` | true |
| 504 | `UPSTREAM_TIMEOUT` | true |

`SERVER_BUSY` 必须同时返回：

```http
Retry-After: 2
```

Outlook 的任何业务错误仍可在顶层附带：

```json
{"credential_update":{"refresh_token":"..."}}
```

所有 `/api/` 响应：

```http
Content-Type: application/json; charset=utf-8
Cache-Control: no-store, private
Pragma: no-cache
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
Content-Security-Policy: default-src 'none'; frame-ancestors 'none'; base-uri 'none'
X-Request-ID: <validated-or-generated-id>
```

401 额外返回 `WWW-Authenticate: Bearer`。有 retry delay 的错误同时在 JSON 和 `Retry-After` header 中返回相同整数。

Request ID 只接受 `[A-Za-z0-9._-]{8,64}`；否则用 `crypto/rand` 生成12 bytes并编码为24位hex。

### 7.5 Health 与旧路径

```text
GET /health/live  → {"status":"ok","version":"1.0.0"}
GET /health/ready → {"status":"ready","mode":"stateless"}
```

readiness 只代表配置、Token hash和内部依赖初始化完成且进程不在 shutdown，不探测 Microsoft/FlySMS。health响应也必须`Cache-Control: no-store`。shutdown期间ready返回503 `{"status":"not_ready"}`。旧 source/UI/docs 路径继续404；错误响应不能落入 Go 默认的 text/plain 页面。

### 7.6 有意的兼容性收紧

对所有符合API调用指南的Python 0.3请求，payload和主要error code保持兼容。以下只影响非法/超载/未文档化边界输入，必须在发布说明中列出：

- 新增`SERVER_BUSY` 503和`Retry-After`；
- 非JSON Content-Type明确415；
- 重复JSON key明确422；
- 输出验证码只接受ASCII六位；
- error/header格式比Python早期413/404分支更统一；
- rate limiter从固定滑动窗改为有界token bucket，并新增burst；
- 推荐调用方整体timeout从75秒提升到90秒。

`wait_seconds`字段本身仍接受0～60；超过部署`max_wait_seconds`时保留422 `HTTP_ERROR`。这些变化不要求合法调用方修改请求JSON。

---

## 8. HTTP Server 设计

推荐 `http.Server`：

```go
&http.Server{
    Addr:              "127.0.0.1:8787",
    Handler:           handler,
    ReadHeaderTimeout: 3 * time.Second,
    ReadTimeout:       10 * time.Second,
    WriteTimeout:      100 * time.Second,
    IdleTimeout:       60 * time.Second,
    MaxHeaderBytes:    16 << 10,
}
```

说明：

- `ReadHeaderTimeout` 防止慢 Header；
- body 只有 128 KiB，10 秒足够；
- `WriteTimeout` 必须覆盖最长 75 秒 provider operation 和响应余量；
- Caddy upstream timeout 建议 ≥105 秒；
- 只监听 loopback；
- 不直接在 Go 中终止公网 TLS，TLS 仍由 Caddy 负责。

### 8.1 中间件顺序

```text
Trusted Host
Request ID
Panic Recovery
Security Headers
Method/Content-Type
Parse + verify Bearer candidate
Consume IP rate token（无论 Bearer 是否有效）
无效 Bearer → 401
Consume principal rate token
Admission
Body Limit + Strict Decode
Handler
```

这保留了 Python 0.3 的重要安全语义：未认证请求也受 IP 限流，攻击者不能用无效 Token 无限打鉴权路径。

Panic recovery 只记录：

```text
request_id
panic category
stack function/file/line
```

不得记录 request/body/header map、局部变量或 `%+v` 展开的第三方 error。生产日志默认不打印完整 panic value。

对于所有在读取body前产生的4xx/503拒绝，若请求声明有body，则响应设置 `Connection: close` 并不主动drain body，避免Go为复用连接而读取/丢弃未授权credential。Caddy或内核可能已经接收部分网络字节，因此这里承诺的是“不解析、不记录、不进入业务对象”，而不是物理上从未进入任何socket buffer。

`Expect: 100-continue` 请求只有在 admission 成功并首次读取 Body 时才发送100响应。

### 8.2 Client IP

只在 `RemoteAddr` 为可信 loopback proxy 时读取：

```text
X-Forwarded-For
X-Real-IP
```

否则忽略代理头，防止伪造 IP 绕过限流。IP使用`net/netip`解析并`Unmap()`；若X-Forwarded-For含多项，从右向左跳过可信proxy，取第一个不可信地址，任何语法错误进入共享`unknown`限流bucket而不是放行。Caddy保持默认覆盖客户端传入的X-Forwarded头，不额外信任公网proxy。

Host校验要正确处理IPv4端口和`[IPv6]:port`，规范化大小写后与非通配`allowed_hosts`精确匹配。只接受一个语法有效的 `Authorization` header，scheme大小写不敏感，Bearer token最长512 bytes。候选 token先做SHA-256，再与所有已加载hash逐一 constant-time比较，不能命中后提前退出。

### 8.3 Token hash 文件与 CLI

Go二进制保留现有运维命令：

```text
coderelay serve --config ...
coderelay validate-config --config ...
coderelay generate-api-token --hash-file ...
coderelay --version
```

Token格式保持 `cr_live_...`，使用`crypto/rand`至少32 bytes熵；文件内容保持 `sha256$<64 hex>`。读取 secret 文件必须使用 `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`、`fstat` regular-file检查、最大1 KiB、owner为service UID且严格0600权限。生成文件使用 `O_EXCL`、0600、flush/fsync，不覆盖已有文件；明文Token只显示一次。

### 8.4 CORS 与 HTTPS scheme

CORS默认关闭。若保留当前 `cors_origins` 配置，只允许精确 origin、POST、`Authorization/Content-Type/X-Request-ID`，`allow_credentials=false`；预检不读取业务body。`X-Forwarded-Proto` 仅在可信loopback Caddy来源时使用。HSTS优先由Caddy统一设置，Go不能信任公网伪造的scheme header。

---

## 9. 20 并发与背压设计

### 9.1 Active + Queue

```text
max_active = 20
max_queue = 4
queue_wait = 2s
```

实现使用两个 bounded channel：

```go
active := make(chan struct{}, 20)
queue  := make(chan struct{}, 4)
```

流程：

1. 尝试立即获得 active；
2. active 满时尝试进入 queue；
3. queue 满，立即 `503 SERVER_BUSY`；
4. queue 成功后最多等待 2 秒；
5. 2 秒内没有 active slot，返回 503；
6. 获得 active 后才读取 JSON body；
7. 所有 return/panic/cancel 使用 defer 释放 slot。

这个模型确保：

- 20 并发全部直接进入；
- 瞬时第 21～24 个可吸收很短抖动；
- 第 25 个立即失败；
- 不存在无界 channel；
- 不存在无界等待 goroutine；
- 排队期间应用层没有解析 credential。

Go不设置 Python式 Provider worker pool，也不把任务再投递到内部工作channel。获得active slot的HTTP handler goroutine直接执行Provider；socket等待由Go netpoll处理。`CGO_ENABLED=0`和`netgo`也避免DNS解析回落到无界cgo工作线程。

active slot一直持有到：Provider清理、响应编码和小响应写入完成。不能在含refresh token的响应发出前提前释放，否则会在进程中积累超过20份敏感响应状态。

### 9.2 共享一个 API Key

推荐：

```text
api_rate_limit_per_minute = 240
api_rate_burst = 40
```

每 IP 和每 API Key fingerprint 各一个 token bucket，取两者中更严格结果。busy请求也消耗已通过的rate token，避免客户端无节制重试。

限流状态本身必须有界：

- IP bucket最多10,000项，principal bucket最多1,000项；
- 64 shard降低锁竞争；
- 每项保存tokens/lastSeen，不保存原始Bearer；
- 后台每分钟清理超过2分钟未访问项；
- map满且没有可清理项时对新key fail-closed返回429；
- cleanup ticker随root context停止。

20 个同 Key 并发只消耗 20 个 token，不会直接触发 240/min 限流。一个项目异常会影响另一个项目，这是共享 Key 的明确运维代价，但用户已接受。

### 9.3 公平性

- 不实现复杂 priority scheduler；
- active channel 对所有 Provider统一；
- TOTP 也需 admission，保证系统总工作量可控；
- 通过极短 TOTP 执行时间自然释放 slot；
- 若后续发现慢邮箱长期饿死 TOTP，再增加保留 fast slots，不在首版过度设计。

---

## 10. Deadline 与轮询语义

Provider attempt timeout：

```text
TOTP：35s（包含等待下一 30s 窗口）
Outlook：30s
FlySMS：45s
```

Operation hard limit：

```text
TOTP：35s
Outlook：30s + wait_seconds，最大 60s
FlySMS：45s + wait_seconds，最大 75s
```

算法严格区分两个deadline：

1. `pollDeadline = resolveStart + wait_seconds`，它只决定“还能不能开始下一次attempt”；
2. 第一次 attempt 无条件开始，并获得完整 Provider attempt timeout；
3. 只有在 `now < pollDeadline` 时才能开始后续 attempt；
4. 一旦 attempt 已开始，不用较短的pollDeadline截断它；
5. `operationDeadline = pollDeadline + attemptTimeout` 是最终安全上限，因此 Outlook最大60秒、FlySMS最大75秒；
6. attempt返回无候选且已经过pollDeadline → `NO_FRESH_CODE`；
7. 单次 attempt 自身耗尽完整timeout → `UPSTREAM_TIMEOUT`；
8. `SOURCE_RATE_LIMITED/SOURCE_SYNCING/UPSTREAM_FAILURE` 只有在等待后仍能于pollDeadline前开始新attempt时才内部重试；
9. 后续轮询间隔2秒并加±10% bounded jitter，避免20个请求同步冲击上游；
10. client disconnect/root shutdown优先cancel，不继续后台工作；
11. 所有 timer必须 `Stop()`，测试注入clock/RNG保持确定性。

该语义准确保留“已经开始的上游读取不被短 `wait_seconds` 截断”，同时禁止在轮询窗口结束后继续启动新读取。operation计时从admission成功、严格JSON解析完成、进入Resolver时开始；最多2秒队列时间由客户端总timeout承担。

调用方整体 timeout 继续建议 90 秒，Caddy upstream timeout ≥105 秒。

### 10.1 Context 与错误分类

- `context.Canceled`且client已断开：停止工作，不尝试写自定义499响应；只增加固定维度cancel counter；
- 子context deadline耗尽：`UPSTREAM_TIMEOUT` 504；
- DNS、TLS、unexpected EOF、connection reset：`UPSTREAM_FAILURE` 502；
- 上游合法HTTP但JSON/MIME契约不支持：`UPSTREAM_SCHEMA_CHANGED` 502且不可盲重试；
- 所有包装使用固定stage和`errors.Is/As`，禁止把URL error、SASL challenge或响应body拼到public/log message。

内部retry次数必须可由代码和测试枚举；除service轮询、一次IMAP重连、一次强制OAuth refresh外，不允许隐式无限重试。

---

## 11. 共享 HTTP Client/Transport

分别创建两个长期对象：

```text
microsoftHTTPClient
flySMSHTTPClient
```

`http.Client.Jar = nil`，因此默认不保存/发送 cookie。

Transport 建议：

```go
&http.Transport{
    Proxy:                   nil,
    DialContext:             (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
    MaxIdleConns:            40,
    MaxIdleConnsPerHost:     20,
    MaxConnsPerHost:         20,
    IdleConnTimeout:         90 * time.Second,
    TLSHandshakeTimeout:     5 * time.Second,
    ResponseHeaderTimeout:   20 * time.Second,
    ExpectContinueTimeout:   1 * time.Second,
    MaxResponseHeaderBytes:  64 << 10,
    Protocols:                microsoftProtocols(), // HTTP/1 + HTTP/2
    TLSClientConfig: &tls.Config{
        MinVersion: tls.VersionTLS12,
    },
}
```

Microsoft和FlySMS始终使用两个独立Transport，避免一个host的连接/拥塞影响另一个。Microsoft Transport的`http.Protocols`启用HTTP/1+HTTP/2。FlySMS Transport只启用HTTP/1：Go会把标准`Authorization`标成HTTP/2 never-index，但自定义`X-Mailbox-Email`可能进入HPACK动态表；为避免邮箱身份残留在共享H2压缩状态中，FlySMS宁可使用最多20条H1 keep-alive连接。该取舍要通过真实压测验证，不能为了少一两个TLS连接牺牲身份隔离。

每次上游请求：

- `http.NewRequestWithContext`；
- 每请求设置 Authorization/header；
- 禁止默认 Authorization；
- 禁止 redirect：`CheckRedirect` 返回错误；
- 响应体使用 `io.LimitReader(body, max+1)`，限制作用于透明解压后的bytes；
- `defer Body.Close()`；
- 只有完整读完的合法小响应才允许drain并复用连接；oversize/解析中止直接Close，不为连接复用继续读攻击内容；
- `Retry-After`同时支持delta-seconds和HTTP-date，结果clamp到1～300秒；
- 关闭服务时 `CloseIdleConnections()`。

`http.Client.Timeout`保持0，所有时限来自显式child context。Microsoft/FlySMS每次HTTP `Do + read`再派生20秒child timeout，外层Provider attempt deadline仍是最终上限。OAuth POST body不设置可自动重放的`GetBody`。推荐用请求级可清零`[]byte` reader，避免Transport在连接错误时重放refresh token；FlySMS GET的网络级安全重试仍由标准库处理。

共享的只有连接池，不是身份状态。

---

## 12. TOTP Provider

### 12.1 输入

- Base32 Secret；
- `otpauth://totp/...`；
- 最大 8 KiB；
- 六位输出；
- 默认 SHA1/30 秒；
- URI 可声明SHA1/SHA256/SHA512，period限制1～86400秒；
- digits必须恰好为6；
- `min_ttl < period`，否则422；
- 拒绝HOTP、重复关键query参数和无法解码的issuer/name。

### 12.2 算法

按照 RFC 6238：

```text
counter = unixTime / period
HMAC(secret, bigEndian(counter))
dynamic truncation
mod 1_000_000
zero-pad 6 digits
```

### 12.3 性能

- 无 HTTP Client；
- 无 goroutine；
- 无 heap-heavy对象；
- Base32 decode 后的 `[]byte` 在 return 前 best-effort 清零；
- 使用 `time.Timer` 等待下一窗口并响应 context cancellation。

### 12.4 测试

- RFC 6238 SHA1/SHA256/SHA512；
- 边界前后 1ns；
- minTTL；
- URI parser；
- 非法 Base32；
- 20 并发同/不同 Secret；
- `-race`。

---

## 13. Outlook Provider

### 13.1 Credential 解析

输入：

```text
email----password----client_id----refresh_token
```

- `SplitN(..., 4)`，refresh token中后续`----`不再拆分；
- email trim后用`cases.Fold()`对齐Python `casefold`；
- password只检查trim后非空，随后不进入domain Credential；
- client ID 必须UUID并规范化为小写连字符形式；
- refresh token 100～65536 Unicode scalar，拒绝任何Unicode whitespace；
- 错误不得包含原始字段。

Go string 也不能保证物理内存清零。实现应尽量使用局部变量和 `[]byte`，请求结束解除引用并对可写 byte slice 清零，但文档不能承诺物理零化。

### 13.2 OAuth

固定：

```text
POST https://login.microsoftonline.com/common/oauth2/v2.0/token
```

Form：

```text
client_id
grant_type=refresh_token
refresh_token
```

不请求 Graph scope，不发送 password。

限制：

- response body ≤1 MiB；
- JSON unknown fields可忽略，但必需字段严格类型；
- access token ≤128 KiB；
- expires_in clamp 60～86400；
- scope若存在，按空白切分并case-insensitive要求 `https://outlook.office.com/imap.accessasuser.all`；
- 429解析Retry-After后映射`SOURCE_RATE_LIMITED`；
- 400中的`invalid_grant/interaction_required/consent_required/login_required`映射`SOURCE_REAUTH_REQUIRED`，其他400和401/403映射`SOURCE_CREDENTIALS_INVALID`；
- 5xx映射`UPSTREAM_FAILURE`，2xx malformed/oversize映射`UPSTREAM_SCHEMA_CHANGED`；
- 禁止 response body 日志。

Form body应直接append percent-encoding到请求级`[]byte`，避免先用`url.Values.Encode()`生成不可清零的大string；request完成后clear。Go的header/string副本仍不能保证物理清零，因此这只是减少副本而非绝对保证。

Microsoft 返回新 refresh token 时写入请求级 `CredentialUpdate`。不论后续是否找到验证码，都要通过成功或错误 JSON交还调用方。同一Provider在一次请求的内部轮询中可复用本次access token；它只在快过期、IMAP认证失败或第二次OAuth refresh时替换，绝不跨HTTP请求缓存。第二次refresh若再次轮换，以最新token作为最终`credential_update`。

### 13.3 IMAP 连接

每个 Outlook 请求使用独立 IMAP TLS connection，不跨请求复用 IMAP session。该session属于请求级Provider：第一次attempt建立，后续2秒轮询优先在同一健康连接上发送NOOP并再次批量读取，从而避免重复TLS/XOAUTH2；请求结束、错误、取消或deadline时必定关闭。协议错误时允许在本attempt预算内重连一次，认证错误则走“强制refresh一次”的专用路径，不能无界重连。

建立流程：

1. `net.Dialer.DialContext`；
2. `tls.Client`；
3. `HandshakeContext`；
4. 设置 conn deadline；
5. `imapclient.New`；
6. greeting/capability；
7. AUTHENTICATE XOAUTH2；
8. `Select("INBOX", ReadOnly=true)`；
9. 根据 `SelectData.NumMessages` 构造最近N封的sequence set并批量FETCH；
10. LOGOUT best-effort；
11. Close conn。

context cancel 时使用 `context.AfterFunc(ctx, conn.Close)` 主动关闭底层 `net.Conn`，并为dial、TLS handshake、auth、fetch分别设置不晚于context deadline的conn deadline，避免库内部Wait永久阻塞。direct TLS必须验证系统CA、SNI=`outlook.office365.com`且最低TLS1.2。LOGOUT只能使用最多1秒cleanup budget；无论LOGOUT结果如何都立即Close，cleanup不得延长业务deadline。

### 13.4 XOAUTH2

实现内部 `sasl.Client`：

```text
mechanism: XOAUTH2
initial response:
user=<email>\x01auth=Bearer <access_token>\x01\x01
```

不记录 challenge/response。XOAUTH2 `Next`收到服务器failure challenge时只返回协议要求的空response，不能把challenge JSON包装进error。initial response使用后立即clear其临时byte slice。认证失败时：

1. 清除本次 access token；
2. 最多强制 OAuth refresh 一次；
3. 再失败映射 `SOURCE_CREDENTIALS_INVALID`；
4. 整个请求最多两次 OAuth refresh。

### 13.5 批量邮件读取

旧 Python 路径逐封 FETCH，网络往返高。Go热路径不执行会返回大量UID的`SEARCH ALL/SINCE`，而直接利用readonly Select已经返回的邮件总数：

```text
EXAMINE/readonly INBOX → NumMessages
→ first = max(1, NumMessages - max_messages + 1)
→ 构造 sequence set first:NumMessages
→ 一次批量 FETCH
```

FetchOptions：

```text
UID=true
InternalDate=true
BodySection Peek=true
BodySection Partial={Offset:0, Size:262144}
```

这比“UID SEARCH + UID FETCH”再少一次网络往返，也避免超大邮箱SEARCH结果在内存展开。FETCH响应中的UID作为稳定message ID；sequence number只用于选取连接快照中的最后N封。

必须使用 streaming `FetchCommand.Next()`，禁止 `Collect()` 收集所有邮件body。即使服务器违反partial请求返回更大literal，仍用`LimitReader(max+1)`检测并立即关闭session。每次只保留：

- 当前邮件≤256 KiB raw；
- 当前邮件的bounded text；
- 候选结果/错误、InternalDate、sequence/UID等少量metadata。

处理完当前raw body后立即释放。为保持Python“按最新邮件优先”的语义，即使服务器按旧→新顺序流式返回，也不能在遇到旧候选时立即return；应只保存每封邮件的提取outcome，最后按`InternalDate DESC, sequence DESC`选择最新合格邮件。某封邮件内部同分多码的`AMBIGUOUS_CODE`也只在该封最终成为最新合格邮件时返回。

freshness最终仍使用InternalDate、extractor max_age和`not_before`做UTC精确过滤。

### 13.6 MIME

使用 go-message/mail streaming reader，并显式加载常见charset支持：

```go
import _ "github.com/emersion/go-message/charset"
```

处理要求：

- RFC 2047 subject；
- quoted-printable/base64；
- text/plain；
- text/html；
- 跳过 attachment；
- part count上限100；
- nested multipart depth上限10；
- subject 10,000 chars、sender 4,096 chars；
- plain/html各自受`max_text_chars`限制；
- normalized text上限；
- 将partial literal导致的预期EOF与真正malformed MIME区分，并用fixture验证截断邮件仍可安全提取已有text part；
- 不渲染HTML；
- 不解压附件；
- 不把正文写磁盘。

### 13.7 go-imap beta 风险门禁

Phase 0 必须证明：

- Outlook AUTH=XOAUTH2 成功；
- ReadOnly Select；
- Peek Fetch 不产生 `\\Seen`；
- single batch sequence FETCH能读取当前真实邮箱；
- context cancel 能关闭连接和所有 goroutine；
- `go test -race` 无数据竞争；
- 100 次连接/关闭后 goroutine/FD 无增长；
- partial literal 不超过限制；
- token/邮件不出现在 debug output。

特别禁止设置 `imapclient.Options.DebugWriter`，其官方文档明确说明可能包含认证凭据。

---

## 14. FlySMS Provider

### 14.1 Credential

```text
email---token---https://flysms.xyz/icloud/pickup#email=...&key=...
```

验证：

- email；
- `tok_` token；
- `tok_[A-Za-z0-9_-]{16,512}`；
- scheme/host按URL规则规范化后必须为https/flysms.xyz；
- 不允许userinfo、显式port、RawPath、query；
- path必须精确`/icloud/pickup`；
- fragment严格解析且只能有唯一的email/key各一次，拒绝重复key、分号和非法percent encoding；
- 两处 email 规范化后必须一致，token 使用 constant-time 比较；
- request URL永远来自 server config，不来自 credential URL。

### 14.2 调用

固定 API：

```text
/icloud/api/pickup/messages/latest
/icloud/api/pickup/messages?limit=30
/icloud/api/pickup/messages/{uid}?mailbox=...
```

顺序：

1. latest；
2. 无候选则 history summary；
3. summary 无正文候选则最多 detail 5 封。

### 14.3 边界

- latest/detail response ≤3 MiB；
- history response ≤1 MiB；
- message list ≤50；
- text ≤1 MiB；
- HTML ≤2 MiB；
- HTTP client timeout20秒/单次网络调用，Provider attempt总预算45秒；
- detail按上游summary顺序最多顺序读取5封，不在一个请求内并行fan-out；
- JSON日期兼容RFC3339/ISO和HTTP mail date，统一UTC；
- response `email`必须与credential casefold后一致；
- entitlement `expired/pending/active/unlimited`映射保持Python语义；
- 401/403/404/429/503/5xx严格映射。

---

## 15. 验证码提取器

保持 Python 版本语义，但用 Go RE2/手工边界实现。

### 15.1 六位边界

Go RE2 不支持 lookbehind/lookahead，因此不直接移植：

```regex
(?<!\d)\d{6}(?!\d)
```

实现方式：扫描恰好六位ASCII digit run，并手工检查前后byte不是ASCII数字。

### 15.2 精确评分语义

Go 1.0必须先保持以下Python 0.3评分，不在重写中顺便“改进算法”：

```text
custom subject = 140 + context - patternIndex
custom body    = 110 + context - patternIndex
generic subject = 70 + context
generic body    = 40 + context
keyword在code前后80字符内：+30
configured subject keyword在当前text任意位置：+15
```

处理细节：

- 先从subject/body移除`http(s)://...`和`www....`，防止URL数字误匹配；
- 同一个code只保留`score`更高、再以position更前者；
- 单封邮件按`score DESC, position ASC, code ASC`排序；
- 前两名不同code同score时返回`AMBIGUOUS_CODE`；
- 邮件按`received_at DESC`，同时间按更高sequence/UID优先；
- 先检查max age/not_before/未来5分钟，再检查sender allowlist；
- sender domain允许精确域和子域；
- generic fallback按配置决定是否必须有keyword；
- 所有输出code强制ASCII `[0-9]{6}`，不接受Unicode数字。

### 15.3 规则

优先级：

1. server-configured named code patterns；
2. sender allowlist/domain；
3. not_before/max age；
4. subject/body keyword context；
5. 最新邮件；
6. 同分多个不同码 → 409。

Go regexp 只允许 RE2 语法。配置加载时：

- 预编译；
- 数量≤20；
- 单条≤512 Unicode scalar；
- 必须有 named group `code`；
- 不支持 lookaround/backreference；
- 编译失败阻止启动。

### 15.4 跨语言 golden fixtures

把 Python 已验证行为导出为语言无关 `testdata`：

```text
input messages
not_before
now
extractor config
expected code/error
```

Go 必须通过所有 golden cases，避免重写时悄悄改变匹配规则。

---

## 16. 凭据生命周期与内存

### 16.1 生命周期

```text
socket receive
→ bounded JSON decoder
→ Secret request field
→ typed credential parser
→ Provider local state
→ upstream request
→ response
→ defer Destroy/release
```

不得把 credential 放入：

- global；
- cache；
- context value；
- error string；
- channel 队列；
- slog Attr；
- metric label。

### 16.2 Secret 类型

建议内部类型：

```go
type Secret struct {
    b []byte
}

func (s *Secret) Destroy() {
    clear(s.b)
    s.b = nil
}

func (s Secret) String() string   { return "[REDACTED]" }
func (s Secret) GoString() string { return "[REDACTED]" }
func (s Secret) LogValue() slog.Value {
    return slog.StringValue("[REDACTED]")
}
func (s Secret) MarshalJSON() ([]byte, error) { return nil, errSecretSerialization }
func (s Secret) MarshalText() ([]byte, error) { return nil, errSecretSerialization }
```

需要承认：标准 JSON 解码和 Go string 可能产生不可写副本，无法承诺物理清零。`Destroy` 是 best effort，不是密码学保证。

### 16.3 禁止敏感 sync.Pool

不对以下 buffer 使用跨请求 `sync.Pool`：

- request JSON；
- credential；
- OAuth form/response；
- MIME raw body；
- normalized message；
- response JSON。

原因是 pool 会把旧数据带到后续请求。性能通过 streaming 和 bounded allocation 获得，而不是复用敏感 buffer。

### 16.4 Refresh token 的无状态交付边界

CodeRelay只能把新refresh token写入当前HTTP响应，不能在客户端断连或响应写失败后恢复它。因此：

- `credential_update`必须在构造任何业务error之前保留；
- 响应写失败后不得把token写日志或磁盘“补偿”；
- 调用方收到任何状态码都先处理`credential_update`；
- 调用方应以“本次提交的旧refresh token”为expected value做原子CAS更新；
- 同一个Outlook credential存在并发刷新时，仅靠CAS仍可能遇到token-family轮换竞争；可靠做法是在调用方触发验证码前按credential加分布式锁，或保证两个项目使用不同Outlook credential。

这与“同邮箱验证码归属”是两个问题，但都不能由无状态CodeRelay在服务端可靠串行化。Go重写不会虚假宣称解决它们。

---

## 17. 内存与 FD 预算

### 17.1 内存预算（20 active）

设计上限估算：

| 项目 | 估算上限 |
|---|---:|
| 20 × 128 KiB request body | 2.5 MiB |
| 20 × 单封 256 KiB streaming IMAP raw | 5 MiB |
| 20 × 100 KiB normalized text | 2 MiB |
| FlySMS bounded JSON/HTML并发峰值 | 约 40～80 MiB |
| HTTP/TLS/IMAP buffers | 约 20～60 MiB |
| Go heap/runtime/code | 压测测量 |

目标：

```text
steady RSS < 256 MiB
stress peak RSS < 512 MiB
peak goroutines < 200（含go-imap内部goroutine）
OS threads < 32
GOMEMLIMIT = 768MiB
systemd MemoryHigh = 768M
systemd MemoryMax = 1G
```

为 Caddy、内核和系统保留至少约1 GiB余量。

### 17.2 FD 预算

20 并发最坏：

```text
20 inbound Caddy connections
20 IMAP sockets
20 OAuth/Fly outbound sockets
idle pool + logs + runtime
```

预计远低于 256 FD。systemd：

```text
LimitNOFILE=4096
```

压测必须验证完成后 FD 回到 baseline。

### 17.3 CPU

生产：

```text
GOMAXPROCS=1
GOMEMLIMIT=768MiB
GOGC=100（先默认，benchmark后再调）
```

不通过增加 worker process 提升吞吐。单进程 goroutine 足以处理20个I/O请求，多进程会重复连接池、限流和内存。

---

## 18. 日志与可观测性

### 18.1 slog

使用 JSON `log/slog`，固定字段：

```text
timestamp
level
request_id
provider
stage
error_code
status
elapsed_ms
```

禁止字段：

```text
credential
email
client_id
access_token
refresh_token
pickup token
code
subject
body
Authorization
完整 URL query/fragment
```

panic/error只记录typed error code，不记录上游response body。日志API采用固定event message和字段白名单；禁止调用`slog.Any("request", req)`、`slog.Any("error", rawErr)`或`fmt.Sprintf`序列化任意对象。

### 18.2 Metrics

默认只使用`sync/atomic`和固定桶记录计数/延迟，不引入Prometheus client热路径依赖。若启用导出，使用单独loopback listener或受限JSON endpoint，不挂到公网ServeMux：

```text
requests_total{provider,status_class}
request_duration_seconds{provider}
inflight_requests
queued_requests
admission_rejected_total
upstream_duration_seconds{provider,stage}
upstream_errors_total{provider,error_code}
canceled_requests_total{provider,stage}
```

provider/stage/error_code都是编译期固定枚举，禁止动态label。禁止以 email、IP、token fingerprint、code、source等作为label。runtime goroutine/heap/GC从`runtime/metrics`按需采样，不在每请求热路径读取。

### 18.3 pprof

- 生产默认关闭；
- 需要时单独绑定 `127.0.0.1`；
- 不经过 Caddy；
- 临时启用后立即关闭；
- heap/profile 文件视为敏感，受限权限并及时删除。

---

## 19. Graceful Shutdown

SIGTERM/SIGINT：

1. readiness立即变为not_ready并关闭admission queue；
2. queue中请求通过shutdown channel立即退出，不再晋升为active；
3. 停止接受新连接；
4. `http.Server.Shutdown`等待active请求，上限90秒；
5. 正常Provider最长75秒，应在grace内完成；
6. grace超时才cancel root context，触发HTTP取消和IMAP conn Close；
7. 关闭HTTP idle connections；
8. 等待清理后退出；若仍超时则非0退出并由systemd接管。

必须测试：

- 20 active 时 SIGTERM；
- client cancel；
- IMAP blocked read；
- OAuth/Fly blocked response；
- admission queue中请求；
- shutdown后 goroutine/FD 无泄漏。

---

## 20. 测试策略

### 20.1 单元测试

- credential parser；
- API JSON strict/discriminated decode、重复key和type-specific extra field；
- 未认证/限流/超载路径不调用自定义Body reader的`Read`；
- Bearer constant-time verification，且无效Bearer仍消耗IP limiter；
- IP/Key token bucket；
- admission20+4；
- TOTP RFC；
- extractor golden；
- HTML tokenizer；
- Retry-After；
- timeout/error mapping；
- refresh token rotation成功/错误/响应写失败；
- no secret in Error/String/GoString/slog；
- Python 0.3 API/error/header golden contract。

### 20.2 Provider 契约测试

Microsoft fake server：

- valid token；
- rotation；
- invalid_grant；
- 429/Retry-After；
- malformed/oversized JSON；
- slow headers/body；
- cancellation。

Fake IMAP TLS server：

- greeting/capability；
- XOAUTH2 challenge；
- readonly Select；
- single batch sequence FETCH；
- literals partial/truncated；
- malformed MIME；
- connection stall；
- logout/close；
- verify no STORE/EXPUNGE/flag mutation。

FlySMS fake server：

- latest/history/detail；
- 401/403/404/429/503/5xx；
- mailbox mismatch；
- entitlement；
- schema/oversize；
- slow/cancel；
- negotiated protocol：Microsoft允许H2，FlySMS必须H1-only。

### 20.3 跨层安全与并发测试

- 20并发相同Key下，fake credential中的唯一标识必须一一映射到预期code；
- client disconnect、half-close和slow response writer；
- no secret in captured application/Caddy logs and temporary filesystem；
- config/token symlink、permission、oversize和`O_NOFOLLOW`；
- 第25个请求的业务Body reader从未被调用；
- 同一refresh token并发rotation的调用方CAS/锁文档测试。

### 20.4 Race

CI：

```bash
CGO_ENABLED=1 go test -race ./...
```

覆盖：

- 20 parallel resolver；
- shutdown；
- shared HTTP clients按Provider协议配置（Microsoft H1/H2；FlySMS H1-only）；
- admission/rate limiter；
- config reload不支持（避免额外 race）。

### 20.5 Fuzz

```text
FuzzOutlookCredential
FuzzFlySMSCredential
FuzzAPIJSON
FuzzMIME
FuzzHTMLToText
FuzzCodeExtractor
FuzzRetryAfter
```

断言：

- 不 panic；
- 不无限循环；
- 不超边界分配；
- 不在 error 中回显输入；
- 运行时间有上限。

---

## 21. 单核 20 并发压测方案

### 21.1 环境

本地/CI：

```bash
taskset -c 0 ./coderelay-go ...
```

VPS final：真实 1 vCPU / 2 GiB。

生产部署不使用 Docker；压测环境可选择 cgroup 约束：

```text
CPUQuota=100%
MemoryMax=2G
```

### 21.2 场景

1. 20 并发不同 TOTP，持续10,000次；
2. 20 并发相同 TOTP，验证一致；
3. 20 并发不同 Outlook fake credential；
4. 20 并发不同 FlySMS fake credential；
5. 8 Outlook + 8 FlySMS + 4 TOTP；
6. 20 active + 4 queue；
7. 第25个请求立即503；
8. 20个请求同时取消；
9. 20 active时SIGTERM；
10. 429/503/timeout故障注入；
11. 60分钟soak；
12. 连续启动/关闭100次；
13. 20个Outlook请求复用各自session多轮poll，验证连接数始终≤20；
14. rate limiter key洪水，验证map上限和cleanup。

### 21.3 验收阈值

本地模拟上游下必须：

```text
20 concurrency: 0 internal 500
credential/result mismatch: 0
race: 0
panic: 0
goroutine leak: 0
FD leak: 0
admission第25请求: p99 <100ms 返回503，且Body未被业务读取
TOTP p99 server overhead: <50ms（不含窗口等待）
模拟Outlook/Fly p99额外server overhead: <500ms（不含注入上游延迟；优化目标<100ms）
20个mock邮件请求首轮均不进入admission queue
cancel后资源回收: <5s
graceful shutdown: <90s，空闲/快速请求场景<5s
steady RSS: <256MiB
stress peak RSS: <512MiB
peak goroutines: <200
OS threads: <32
```

上游真实延迟不计入本地 overhead，但必须落入预期 timeout/error code。

通过标准不是“平均成功”，而是所有20个并发都有正确、可解释结果。

---

## 22. 性能分析工具

实现中必须提供：

```bash
go test -bench . -benchmem ./...
go test -race ./...
go test -fuzz ...
go vet ./...
staticcheck ./...
govulncheck ./...
```

性能诊断：

```text
runtime/pprof CPU
heap
allocs
block
mutex
goroutine
runtime/trace
```

Go 1.26 提供实验性 goroutine leak profile，可在测试环境评估，但不作为生产必需特性。

每次重要优化记录：

```text
before benchmark
hypothesis
change
after benchmark
RSS/goroutine/FD
```

---

## 23. 构建与供应链

### 23.1 生产构建

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build \
  -trimpath \
  -tags netgo,osusergo \
  -ldflags "-s -w -X main.version=${VERSION}" \
  -o dist/coderelay \
  ./cmd/coderelay
```

验证：

```bash
file dist/coderelay
ldd dist/coderelay   # 应显示 not a dynamic executable
sha256sum dist/coderelay
./dist/coderelay --version
# 目标VPS还必须验证 /etc/ssl/certs CA bundle、DNS和NTP状态
```

`CGO_ENABLED=0`消除了glibc版本依赖，但二进制仍依赖目标机的Linux kernel、CA证书、DNS配置和正确系统时间。TOTP、`not_before`和TLS都要求VPS启用NTP。

发布同时保留一个不使用`-s -w`的受限debug artifact，便于离线符号化；生产只部署stripped binary。构建输出还应包含Go build info、SBOM、SHA-256和GitHub artifact provenance/attestation。

### 23.2 依赖固定

- `go.mod` + `go.sum`；
- go-imap beta建议 vendor；
- CI 使用 `-mod=vendor`；
- 禁止 floating pseudo version 升级；
- 升级依赖必须重新跑 real Outlook gate和20并发压测；
- 生成 SBOM；
- `staticcheck`、`govulncheck`、SBOM工具本身也在CI中pin版本；
- 发布 SHA-256。

### 23.3 CI

Jobs：

```text
unit-go1.25
unit-go1.26
race
fuzz-smoke
staticcheck-vet-govulncheck
linux-amd64-static-build
linux-arm64-static-build（可选）
loadtest-1cpu
```

任何 job失败不得发布。

---

## 24. 部署配置建议

Go配置优先保留Python 0.3现有字段名，新增字段使用同一命名风格：

```toml
[server]
host = "127.0.0.1"
port = 8787
allowed_hosts = ["2fa.077.li", "localhost", "127.0.0.1"]
cors_origins = []
forwarded_allow_ips = "127.0.0.1,::1"
access_log = false
log_level = "info"
max_wait_seconds = 30
http_connect_timeout_seconds = 5.0
http_read_timeout_seconds = 20.0
http_max_connections = 20
max_concurrent_code_requests = 20
max_queued_code_requests = 4
admission_wait_seconds = 2.0
read_header_timeout_seconds = 3.0
read_timeout_seconds = 10.0
write_timeout_seconds = 100.0
idle_timeout_seconds = 60.0
shutdown_timeout_seconds = 90.0
max_header_bytes = 16384
max_body_bytes = 131072

[security]
api_token_hash_files = ["/etc/coderelay/secrets/api-shared.sha256"]
strict_secret_permissions = true
api_rate_limit_per_minute = 240
api_rate_limit_burst = 40
max_ip_rate_limit_entries = 10000
max_principal_rate_limit_entries = 1000

[providers.outlook]
token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
imap_host = "outlook.office365.com"
imap_port = 993
imap_timeout_seconds = 15.0
fetch_timeout_seconds = 30.0
poll_interval_seconds = 2.0
max_messages = 10
max_message_bytes = 262144

[providers.flysms]
base_url = "https://flysms.xyz/icloud/api/pickup/messages"
fetch_timeout_seconds = 45.0
poll_interval_seconds = 2.0
history_limit = 30
max_detail_messages = 5
```

两套`providers.*.extractor`字段原样保留。所有固定上游URL/host/port继续使用literal allowlist，配置成其他地址必须启动失败。TOML unknown field、重复table、越界值或相互矛盾timeout均使`validate-config`和`serve`fail closed。

启动时至少验证以下关系：

```text
maxOperation = max(outlookFetchTimeout, flysmsFetchTimeout) + max_wait_seconds
http_max_connections >= max_concurrent_code_requests
api_rate_limit_burst >= max_concurrent_code_requests
max_queued_code_requests <= max_concurrent_code_requests
writeTimeout >= admissionWait + maxOperation + 10s
shutdownTimeout >= maxOperation + 5s
Caddy responseHeaderTimeout > writeTimeout
systemd TimeoutStopSec > shutdownTimeout
```

默认值下`maxOperation=75s`、`writeTimeout=100s`。若管理员把`max_wait_seconds`提高到60而不同时提高外层timeout，Go必须拒绝启动，不能生成运行一半才发生的伪504。

systemd：

```ini
[Service]
User=coderelay
Group=coderelay
UMask=0077
ExecStart=/usr/local/bin/coderelay serve --config /etc/coderelay/config.go.toml
Environment=GOMAXPROCS=1
Environment=GOMEMLIMIT=768MiB
Restart=on-failure
RestartSec=2
TimeoutStopSec=100
LimitNOFILE=4096
LimitCORE=0
TasksMax=128
MemoryHigh=768M
MemoryMax=1G
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectHostname=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictRealtime=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
```

不启动多个 Go worker/process。`GOMEMLIMIT`是runtime软限制，`MemoryMax`是cgroup硬限制；不能把两者设成同一个值，否则GC没有余量。

### 24.1 Caddy

建议保持单upstream且不配置主动重放POST：

```caddyfile
2fa.077.li {
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"

    reverse_proxy 127.0.0.1:8787 {
        transport http {
            dial_timeout 5s
            response_header_timeout 105s
        }
    }
}
```

Caddy访问日志不得包含Authorization、request/response body或query token；默认不会记录body，但必须审查自定义log format。防火墙只开放443，8787只监听loopback。Go服务100秒write timeout、Caddy 105秒header timeout、调用方90秒整体timeout形成由内到外递增的明确边界。

### 24.2 配置与回滚文件

Go新增字段会被Python的`extra=forbid`拒绝，所以不能虚假宣称同一文件可无损双用。部署时保留：

```text
/etc/coderelay/config.python.toml
/etc/coderelay/config.go.toml
/etc/coderelay/secrets/api-shared.sha256
```

两种实现共享同一个Token hash文件和API契约，但各自使用已验证配置。切换/回滚时必须先运行目标二进制的`validate-config`。

---

## 25. Python → Go 迁移计划

### Phase 0：风险原型

只实现：

```text
OAuth refresh
XOAUTH2
readonly IMAP
Select NumMessages
single batch partial sequence FETCH（返回UID/InternalDate）
request-scoped session NOOP复用
MIME parse
context cancel/conn deadline
```

用真实 Outlook 验证 go-imap beta.8。失败则先处理 Adapter 选择，不进入全面重写。

### Phase 1：基础服务 + TOTP

- config；
- Bearer；
- rate/admission；
- error JSON；
- health；
- TOTP；
- 静态二进制；
- 20并发TOTP。

### Phase 2：FlySMS

- credential parser/SSRF；
- shared no-cookie transport；
- latest/history/detail；
- contract/fuzz/fault tests。

### Phase 3：Outlook

- OAuth；
- rotation；
- IMAP Adapter；
- batch streaming FETCH；
- MIME；
- cancel/shutdown。

### Phase 4：Extractor parity

- 导入 Python golden fixtures；
- RE2规则和ASCII六位边界；
- Unicode casefold parity；
- HTML；
- ambiguity；
- not_before。

### Phase 5：并发与安全收口

- 20+4 admission；
- one-key 240/min；
- race/fuzz；
- pprof；
- 1CPU load/soak；
- credential log scans；
- 更新API调用指南：共享Key、`SERVER_BUSY`、90秒timeout；
- static binary。

### Phase 6：真实验收

- 三类真实 credential通过 `POST /api/v1/code`；
- Outlook rotation成功/错误响应；
- 20并发真实或安全测试账号；
- VPS/Caddy；
- 从两个实际调用项目主机测试；
- 真实测试结束后轮换所有在聊天、终端或人工验收中暴露过的上游credential。

### Phase 7：切换与回滚

保持同一域名/API，切换 systemd binary。payload契约不变，但两个调用项目上线前必须把整体timeout从当前75秒调整为90秒，并新增`SERVER_BUSY`有限退避处理。

```text
coderelay-python 0.3.0 保留为 rollback
coderelay-go 1.0.0 先运行在备用端口
Caddy canary切少量请求
完成验收后切全部
```

禁止把同一个Outlook/FlySMS请求同时镜像到Python和Go：重复OAuth刷新会放大token轮换竞争，重复上游读取也不能提供可靠差分。TOTP可以shadow；邮件Provider使用合成fixture、独立测试credential或一次只路由到一个实现。

切换前为当前提交创建`python-v0.3.0` tag和可校验binary。Go收到的最新refresh token由调用方保存，因此回滚后的Python会在下一请求收到最新四段式credential，无服务端状态迁移。

Go 配置保留当前稳定字段名，但新增安全/并发字段使文件不能直接交给Python；回滚使用第24.2节的独立已验证配置。不得在 Go 验收前删除 Python tag、binary、文档和测试基线。

---

## 26. 发布门禁（Definition of Done）

Go 1.0.0 只有全部满足才可替代 Python：

- [ ] API 请求/响应兼容；
- [ ] 同一 CodeRelay Key 20并发；
- [ ] 20并发无 credential/result串用；
- [ ] admission20+4行为通过；
- [ ] 第25个请求快速503；
- [ ] TOTP RFC全部通过；
- [ ] Outlook OAuth/XOAUTH2真实通过；
- [ ] Outlook readonly/Peek/未读状态通过；
- [ ] Outlook batch FETCH通过；
- [ ] Outlook token rotation在成功和错误响应均通过；
- [ ] FlySMS真实邮件读取通过；
- [ ] Python extractor golden parity通过；
- [ ] `go test -race ./...`通过；
- [ ] fuzz smoke通过；
- [ ] 60分钟单核soak通过；
- [ ] RSS/FD/goroutine阈值通过；
- [ ] cancel/shutdown无泄漏；
- [ ] 日志/二进制/Git credential扫描通过；
- [ ] `govulncheck`通过；
- [ ] CGO=0静态二进制通过；
- [ ] amd64 artifact/checksum通过；
- [ ] VPS实际1核2G验收通过；
- [ ] 两个实际调用项目端到端通过；
- [ ] 所有聊天/人工验收中暴露过的TOTP、Outlook、FlySMS凭据已轮换；
- [ ] rollback演练通过。

---

## 27. 主要风险与控制

| 风险 | 控制 |
|---|---|
| go-imap v2仍为beta | Adapter隔离、pin beta.8、vendor、Phase0真实门禁、回退方案 |
| 重写改变提取语义 | 语言无关golden fixtures |
| 20并发内存峰值 | streaming、body limits、GOMEMLIMIT、MemoryMax、soak |
| goroutine/conn泄漏 | context close、race、goroutine/FD baseline、shutdown tests |
| 共享Key互相限流 | 240/min + burst40，用户接受共享故障域 |
| 上游长延迟 | attempt/operation硬deadline、typed errors |
| credential出现在日志 | Secret类型、slog白名单字段、日志扫描 |
| buffer复用泄漏 | 敏感数据禁止sync.Pool |
| 依赖供应链 | go.sum/vendor/govulncheck/SBOM |
| 单核CPU峰值 | 连接池、批量FETCH、bounded parse、pprof |
| 超载时credential堆积 | admission在body decode之前，pre-body拒绝不drain并关闭连接 |
| token轮换响应写失败 | 不持久化补偿；调用方CAS更新并避免同credential并发刷新 |
| Python/Go配置分歧 | 保留两份已验证配置，切换前validate-config |
| Unicode/regex语义变化 | x/text casefold、ASCII code决策、golden差分测试 |
| Caddy意外重放POST | 单upstream、无retry配置、故障注入确认 |

---

## 28. 参考资料与已核对事实

1. Go 1.26 Release Notes：`https://go.dev/doc/go1.26`
   - 2026-02发布；
   - Go 1兼容承诺；
   - Green Tea GC默认启用；
   - 提供goroutine leak profile实验能力。
2. Go `net/http`：`https://pkg.go.dev/net/http`
   - Client/Transport可并发安全复用；
   - 官方建议复用以提高效率；
   - Server提供Read/Write/Idle/Header边界。
3. go-imap：`https://github.com/emersion/go-imap`
   - v2为IMAP4rev2库；
   - 当前仍处于开发/beta。
4. go-imap v2 client docs：`https://pkg.go.dev/github.com/emersion/go-imap/v2/imapclient`
   - 支持ReadOnly Select、UIDSearch、Fetch partial/Peek、streaming Fetch；
   - Client可多goroutine使用；
   - DebugWriter可能包含认证凭据，生产禁止。
5. go-imap release：`v2.0.0-beta.8`，2026-02-07发布。
6. go-sasl：`https://pkg.go.dev/github.com/emersion/go-sasl`
   - 原生OAUTHBEARER；
   - Outlook所需XOAUTH2由项目内部实现最小SASL Client。
7. go-toml：`v2.4.3`，2026-07-05发布。
8. `golang.org/x/net`：当前查询版本 `v0.57.0`。
9. `golang.org/x/text`：当前查询版本 `v0.40.0`，用于Unicode casefold parity。
10. `runtime/debug.SetMemoryLimit`：`https://pkg.go.dev/runtime/debug#SetMemoryLimit`
   - 提供Go runtime软内存上限；
   - 可由`GOMEMLIMIT`设置。

所有依赖版本在真正开工时应再次核对并通过 `govulncheck`，不自动升级。

---

## 29. 最终建议

本次 Go 重写是合理的，因为项目已经收敛为小而明确的 API-only、无状态、三 Provider 服务，且目标环境为 1 vCPU/2 GiB 单文件 VPS。

但“性能做到极致”应解释为：

```text
最少网络往返
有界资源
正确取消
稳定连接池
流式解析
明确背压
可测量、可回滚
```

而不是牺牲验证、timeout、credential隔离或错误语义换取单次 benchmark 数字。

首个实施动作必须是 Phase 0 的真实 Outlook Go 原型。go-imap beta 风险未通过门禁前，不开始替换主分支实现。
