# CodeRelay Go 重写进度

更新时间：2026-08-04

## 总览

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0：真实 Outlook 风险原型 | ✅ PASS | `go-imap/v2 beta.8` 路径通过；细节见 `prototypes/outlook-go/RESULTS.md` |
| Phase 1：基础服务 + TOTP | ✅ PASS | 正式 Go 模块、HTTP 骨架、TOTP 和 20 并发门禁完成 |
| Phase 2：FlySMS | ✅ PASS | contract/fuzz/fault、真实 `NO_FRESH_CODE` 和真实 HTTP 200 六位码均通过 |
| Phase 3：Outlook 正式实现 | 🟡 实现中 | 显式 IMAP/Graph 双模式、rotation、bounded读取与本地 hardening 已完成；Graph/IMAP 新鲜码、成功 rotation、未读保持和真实部署门禁仍待完成 |
| Phase 4：Extractor parity | ✅ PASS | 48 个冻结 parity fixtures + 日文/葡萄牙语经审核扩展；contract 覆盖 ASCII 边界、RE2、casefold、HTML、sender、多语言 keyword、fallback、ambiguity、freshness、not_before、最新 UID |
| Phase 5：并发与安全收口 | ✅ PASS | 原 Phase 5 资源门禁全部通过；Phase 5.5 增加显式 Outlook `mail_access=imap|graph`、Graph身份绑定、只读Inbox/preview/MIME与bounded polling |
| Phase 6：真实验收 | 🟡 待外部门禁 | Graph真实自测已证明授权可用；仍需使用Phase 5.5正式二进制完成fresh-code、rotation、未读状态和VPS/Caddy/消费端验收 |
| Phase 7：切换与回滚 | ⬜ 未开始 |  |

仓库现已只保留 Go 服务、Go 测试和语言无关 golden fixtures，旧服务源代码、依赖、测试、配置、构建路径及本地构建环境已移除。Phase 3 尚未完成新鲜 Outlook HTTP 200、成功响应 rotation、显式未读状态和真实部署门禁；仓库 Go-only 不等于 Phase 6/7 已通过。

---

## Phase 1～5 交付（Phase 5 并发、安全与 Go-only 收口）

正式代码位于：

```text
cmd/coderelay/
cmd/phase5-soak/
internal/
  admission/
  api/
  auth/
  config/
  credential/
  domain/
  extractor/
  provider/flysms/
  provider/outlook/
  ratelimit/
  secretfile/
  service/
  totp/
  version/
```

配套文件：

```text
go.mod
go.sum
config.example.toml
scripts/build.sh
scripts/generate-sbom.sh
scripts/profile-phase5.sh
```

已实现：

- [x] 严格 TOML 配置及 unknown-field rejection；
- [x] 仅允许 loopback 监听；
- [x] 固定 Host allowlist；
- [x] 只信任 loopback Caddy 的转发 IP；
- [x] Bearer Token 鉴权；
- [x] `sha256$<64 hex>` Token hash 文件；
- [x] secret 文件 `O_NOFOLLOW`、owner/mode/size 检查；
- [x] Token 生成及 mode-0600 exclusive write；
- [x] 无效 Bearer 也消耗 IP rate token；
- [x] IP 和 principal 独立、有界、分片 token bucket；
- [x] 128 条 inbound connection hard cap（约束 net/http request goroutine 和 connection FD）；
- [x] 20 active + 4 queue + 2 秒 admission；
- [x] 超载在读取 JSON credential 前返回 `503 SERVER_BUSY`；
- [x] 统一 JSON error、request ID 和安全响应头；
- [x] `GET /health/live`；
- [x] `GET /health/ready`；
- [x] `POST /api/v1/code`；
- [x] 严格 discriminated JSON、重复 root key 拒绝、128 KiB body limit；
- [x] Base32 和 `otpauth://totp/...`；
- [x] SHA1/SHA256/SHA512、六位输出和 period/min_ttl；
- [x] FlySMS 三段式 credential parser；
- [x] email/token/URL 一致性和 constant-time token 比较；
- [x] 固定 `https://flysms.xyz/icloud/api/pickup/messages`，拒绝 userinfo/port/query/非规范 fragment；
- [x] 独立、无 Cookie、禁代理、禁 redirect、HTTP/1-only Transport；
- [x] latest → history → 最多 5 条 detail；
- [x] 1 MiB history、3 MiB latest/detail 和字段级边界；
- [x] entitlement、401/403/404/429/503/5xx/timeout 映射；
- [x] 45 秒 attempt、20 秒单 HTTP、0～30 秒 polling；
- [x] request-scoped Secret、best-effort clear、日志/序列化脱敏；
- [x] Outlook credential parser（password 兼容字段不进入 domain）及 OAuth refresh/rotation；
- [x] Outlook direct TLS、XOAUTH2、readonly `INBOX`、同一请求内 session/NOOP 轮询；
- [x] Outlook Graph no-scope refresh、`/me`身份绑定、readonly Inbox list、preview-first/bounded MIME fallback；
- [x] Outlook请求显式`mail_access=imap|graph`，省略兼容IMAP且拒绝auto probing；
- [x] UID/InternalDate、单次批量 streaming `BODY.PEEK` partial FETCH、bounded MIME 解析；
- [x] 成功与业务错误响应的 `credential_update` 传播；
- [x] graceful shutdown 基础；
- [x] CGO=0 Linux amd64 静态二进制；
- [x] Go 1.25.12 / 1.26.5 CI；
- [x] race、全套 fuzz smoke、staticcheck、govulncheck；
- [x] 共享 `testdata/extractor_golden.json` fixtures（48 个 Phase 4 baseline + 1 个经审核的日文扩展）；
- [x] ASCII 六位数字边界、lookaround 等价手工扫描和 Unicode 数字拒绝；
- [x] Go RE2 custom named `code` pattern 与启动时配置校验；
- [x] Unicode casefold、HTML visible text、script/style/head/noscript/svg/template 跳过；
- [x] sender exact/domain、subject keyword、custom pattern、generic fallback、ambiguity；
- [x] `not_before`、最大邮件年龄、未来 5 分钟边界、最新邮件/UID 优先；
- [x] canonical fixture contract：50/50 code/error 结果通过；
- [x] FIFO queue，queued request 不能被新请求 bypass/starve；
- [x] 240/min、burst 40 的 IP/principal bucket 和 10,000/1,000 状态硬上限；
- [x] 第 25 个请求 `<100 ms` `503 SERVER_BUSY`，body reads=0；
- [x] queue timeout 和 shutdown rejection 均不读取 credential body；
- [x] client cancel、provider cancel、graceful shutdown 和 deadline force-cancel 测试；
- [x] SIGUSR1 bounded runtime snapshot，不开放 HTTP pprof/debug/metrics；
- [x] `cmd/phase5-soak`：单核、共享 key、20-request paced bursts、结构化日志 secret/code scan；
- [x] offline CPU/heap pprof benchmark；
- [x] reproducible `-buildvcs=false` static binary、SHA-256 和 CycloneDX 1.6 SBOM；
- [x] 旧服务实现、依赖、测试、配置和构建路径全部删除；仓库仅保留 Go。

## Phase 5 验收结果

```text
admission:
  active: 20
  FIFO queue: 4
  queue wait: 2s
  25th request: 10/10 <100ms, max 83.97µs, body reads 0
shared principal bucket:
  240/minute, burst 40: PASS
IP/principal bounded state:
  10,000 / 1,000 caps: PASS
20-request single-core soak bursts:
  duration: 3,600.0007s
  cycles: 686
  requests: 13,720 (minimum 13,700)
  HTTP 200: 13,720
  HTTP 500: 0
  credential/result mismatch: 0
  p99/max latency: 4.619s / 4.621s
  goroutines before/peak/after: 8 / 48 / 8
  goroutine leak: 0
  FDs before/peak/after: 6 / 26 / 6
  FD leak: 0
  sockets peak: 21
  threads peak: 7
  RSS before/peak/after: 8.4 / 14.1 / 13.8 MiB
  steady RSS peak: 14.1 MiB (<256 MiB)
  stress RSS peak: 14.1 MiB (<512 MiB)
  structured log credential/code matches: 0
  SIGTERM shutdown: 3.161ms, clean exit
cancellation/shutdown:
  client cancel: PASS
  provider cancellation mapping: PASS
  forced shutdown deadline: PASS
offline pprof:
  BenchmarkPhase5TOTPHandler: 19.876µs/op, 12,664 B/op, 126 allocs/op
  CPU and heap profiles: PASS
supply chain:
  CGO=0 static binary: PASS
  binary size: 9,314,466 bytes
  SHA-256: ae5f12a0a8ff72394d903e9ef8ad06b81a1a141781be435825513a24f17642b9
  CycloneDX SBOM 1.6 / cyclonedx-gomod v1.10.0: PASS
  GitHub CI: https://github.com/LinYS77/coderelay/actions/runs/30747314889 (5/5 jobs, 60/60 steps)
Go-only cleanup:
  legacy runtime/build artifacts: 0
  current-tree legacy artifacts: 0
```

## Phase 5.6 Portuguese verification-code keywords

真实 OpenAI 验证邮件（巴西葡萄牙语）中的六位码此前因缺少葡萄牙语 keyword 被 `generic_requires_keyword=true` 安全忽略：

- 增加默认葡萄牙语语义词：`código de verificação`、`código de segurança`、`código de confirmação` 及去掉重音变体 `codigo de verificacao`、`codigo de seguranca`、`codigo de confirmacao`；
- 增加与真实结构等价、但使用合成数字的 OpenAI 风格葡萄牙语 regression（plain text、golden fixture、base64 MIME 三层）；
- 继续只接受 ASCII `[0-9]{6}`；`fold` 统一大小写（含重音字母），URL 剥离、freshness、sender、ambiguity 规则不变；
- golden contract 由 49 个冻结 case 增至 50 个，50/50 通过。

```text
version: CodeRelay Go 1.0.0-phase5.6
binary size: 9,384,098 bytes
SHA-256: 4c20b2bab85ca12c3debf95be0c2954c858269112208e4c8bed125a7c7e14cb7
canonical fixtures: 50/50
```

## Phase 5.5 Outlook explicit IMAP/Graph mailbox access

真实 credential 证明同一 client/user grant 可以取得带 `User.Read`、`Mail.Read`、`Mail.ReadWrite` 的 Graph token，但显式 IMAP scope 返回 `invalid_grant`，且 Graph token 无法用于IMAP XOAUTH2。Phase 5.5据此修正“Outlook账号等于IMAP授权”的错误建模：

- 公共请求新增可选 `mail_access=imap|graph`；省略保持IMAP，拒绝`auto`；
- IMAP模式继续显式请求固定IMAP scope；Graph模式refresh form完全省略scope；
- Graph token scope存在时要求`User.Read`及`Mail.Read|Mail.ReadWrite`，`Mail.ReadBasic`单独存在会要求重新授权；
- Graph固定调用`/me`并要求mail或userPrincipalName与credential email匹配；
- 只对固定Graph v1.0 endpoint发GET：Inbox list、bodyPreview、必要时bounded MIME `$value`；
- 不跟随`@odata.nextLink`，不使用caller URL，不发送/PATCH/DELETE/标记已读；
- request-local MIME去重≤50 IDs/128 KiB，list调用≤70，JSON≤1 MiB，MIME继续服从`max_message_bytes`；
- Graph 401最多强制refresh一次，403/429/5xx/timeout/schema分别稳定映射；
- success、`NO_FRESH_CODE`、identity/scope/upstream错误均保留最新rotation；
- 20个并发Graph credential race回归证明无credential/result串用；
- 新增固定stage：`outlook_graph_scope`、`outlook_graph_identity`、`outlook_graph_list`、`outlook_graph_message`；
- 架构决策见`docs/adr/0001-outlook-explicit-mail-access.md`。

```text
version: CodeRelay Go 1.0.0-phase5.5
binary size: 9,384,098 bytes
SHA-256: 028929348b8111ebc686a3ba741d788cfaef6fb3e968a2405d0609df211420e9
local/fake Graph gates: PASS (dual toolchains, race, 20-concurrency ×100, JSON/MIME fuzz, vet/staticcheck/govulncheck)
real Graph formal CodeRelay gate: pending external credential/VPS run
```

## Phase 5.4 Japanese verification-code extraction hotfix

针对 US IP 触发英文邮件时可提取、其他地区触发日文邮件时返回 `NO_FRESH_CODE` 的情况：

- 根因是默认 keyword 只有中文与英文；日文正文中的 ASCII 六位数因 `generic_requires_keyword=true` 被安全地忽略；
- 增加语义明确的日文默认词：`検証コード`、`認証コード`、`確認コード`、`セキュリティコード`、`ワンタイムコード`、`ワンタイムパスワード`、`パスコード` 及常见空格变体；
- 增加与真实结构等价、但使用合成数字的 `一時検証コード` plain-text regression；
- 增加 UTF-8/base64 MIME → extractor 集成回归，确认问题不在日文 MIME 解码；
- 更新配置示例中的日文 subject keywords 与 RE2 named-code pattern；
- 继续只接受 ASCII `[0-9]{6}`，不把全角或其他 Unicode 数字归一化为验证码；
- 原有 sender、freshness、`not_before`、URL stripping 和 ambiguity fail-closed 规则保持不变。

```text
version: CodeRelay Go 1.0.0-phase5.4
binary size: 9,318,562 bytes
SHA-256: 1b9f9b1e5951fa9c871394441cad181a569aab0b9fc0443a2386d5e92768dd49
canonical fixtures: 49/49
```

## Phase 5.3 Outlook compatibility and session-reuse hotfix

Phase 5.3 当时针对“希望使用IMAP的credential”修复了默认资源选择问题。后续Phase 5.5真实证据确认，最初报告的特定credential实际只具备Graph邮件授权；因此本节不是该credential最终根因，只保留为IMAP模式的正确性修复：

- IMAP模式的OAuth refresh显式发送官方完整 scope `https://outlook.office.com/IMAP.AccessAsUser.All`，避免依赖默认资源选择；Graph模式不使用此scope；
- `invalid_scope` 和 OAuth 成功响应中的错误 scope 映射为 `SOURCE_REAUTH_REQUIRED`；
- 对含 `!`、`*`、`$`、`_`、`-` 的 opaque refresh token 增加 form round-trip regression，确认编码不改写 token；
- 增加固定、无敏感信息的 `source_stage` 日志：`outlook_oauth_token`、`outlook_oauth_scope`、`outlook_imap_auth`；
- go-imap 的异步 mailbox snapshot 在 `Select.Wait` 后仍可能短暂为 `nil`；现在使用 `SelectData.NumMessages` 作为权威 fallback，并在 NOOP 后更新 snapshot，避免把瞬态空 snapshot 误判成 FETCH 故障而重连；
- race/scheduler pressure 回归从可复现的 `session opens = 2` 修复为 12 个并行进程 × 每进程 1,000 次全部保持单 session；
- OAuth body、Microsoft error description、email、access/refresh token 仍不会记录或返回。

```text
version: CodeRelay Go 1.0.0-phase5.3
binary size: 9,318,562 bytes
SHA-256: f761b0631d27da90a548abf785ffe279297384bc83d6d100fd90b1b858688000
```

## Phase 4 验收结果（冻结 extractor contract）

```text
fixtures: 48
Golden contract: 48/48
Go golden: 48/48
code/error mismatch: 0
Go regression (both supported toolchains): PASS
Go 1.25.12 / 1.26.5 tests: PASS
race / vet / staticcheck / govulncheck: PASS
FuzzExtractor smoke: PASS
CGO=0 linux/amd64 static build: PASS
version: CodeRelay Go 1.0.0-phase4
size: 9,298,082 bytes
SHA-256: b2db3a18cd314460d1a579de28d3d94ab330e213ad6ff84c8765e807b7d05cbc
GitHub CI: https://github.com/LinYS77/coderelay/actions/runs/30742853076（7/7 jobs success）
```

执行入口：

```bash
go test -count=1 ./internal/extractor
```

## Phase 1～2 验收结果（Phase 3 之前的已完成门禁）

受控 handler 测试：

```text
20 concurrent TOTP: 20/20 HTTP 200
credential/result mismatch: 0
internal 500: 0
p99/max handler overhead, GOMAXPROCS=1 (10 runs): 0.055～0.117 ms
requirement: <50 ms
```

真实静态二进制 loopback smoke：

```text
health/live: 200
health/ready: 200
unauthenticated POST: 401
20 different TOTP credentials: 20/20
credential/result mismatch: 0
internal 500: 0
network p99, GOMAXPROCS=1: 7.206 ms
application log secret matches: 0
SIGTERM graceful stop: PASS
```

### FlySMS Phase 2

合成 contract / fault 门禁：

```text
latest / history / detail：PASS
email/token/header identity：PASS
entitlement active/unlimited/expired/pending：PASS
401/403/404/429/503/5xx：PASS
HTTP timeout / cancel / read fault / malformed / oversize：PASS
redirect destination hits：0
Cookie persistence：0
negotiated protocol：HTTP/1.1
successful keep-alive requests / connections：2 / 1
20 parallel credentials：20/20，identity/code mismatch 0
detail fan-out cap：5
```

真实 FlySMS credential，经最终 Go HTTP API：

```text
mailbox read：PASS
无新鲜码：HTTP 404 / NO_FRESH_CODE / 1.236 s
新鲜邮件：HTTP 200
返回 JSON keys：仅 code
code shape：ASCII six-digit PASS
fresh-code elapsed：0.306 s
credential/code application-log matches：0
```

第一次新鲜码探针使用的 `not_before` 晚于上游实际邮件接收时间，因此正确返回 `NO_FRESH_CODE`。脱敏诊断确认新邮件接收时间后，将 `not_before` 调整到实际触发窗口内，同时仍排除约两小时前的旧邮件；最终二进制返回 HTTP 200 和唯一六位 `code`。真实 credential 的有新鲜码与无新鲜码两条门禁均已通过。

Admission：

```text
20 active: admitted
21～24: bounded queue
25th: <100 ms → 503 SERVER_BUSY
25th business Body reads: 0
queued shutdown exit: PASS
active graceful completion: PASS
```

质量门禁：

```text
Go tests: 117 passed / 14 packages
go test -race: PASS
FuzzDecodeRootObject / TOTP / FlySMS credential / response / Retry-After smoke: PASS
staticcheck v0.7.0: PASS
govulncheck reachable vulnerabilities: 0
CI: https://github.com/LinYS77/coderelay/actions/runs/30733137080 (success)
```

构建产物（本地、未提交）：

```text
dist/coderelay-go
size: 7,631,010 bytes
SHA-256: 8203cfa0a8a35fb998323464f60f7644535a6446a039a1480300ea8a002e9227
ELF x86-64, statically linked, stripped
```

## Phase 3 当前验证（历史记录，最终制品见 Phase 5）

```text
Go tests (含 Outlook parser/OAuth/IMAP/MIME/API update)：PASS
Go 1.25.12 / 1.26.5 tests：PASS
vet / race / staticcheck / govulncheck：PASS（reachable vulnerabilities: 0）
Outlook credential/MIME fuzz smoke：PASS
CGO=0 linux/amd64 static build：PASS
SHA-256：aa34b28e73ff380d205cac0fa2e94eeceb95a01a96f10958bddedfce6886127b

真实正式二进制 loopback 门禁：
health/ready：HTTP 200
OAuth refresh + IMAP XOAUTH2 + readonly batch FETCH：PASS（HTTP 404 NO_FRESH_CODE）
错误响应 credential_update：PASS；轮换 token 已写入新的 caller-managed 0600 文件
SIGTERM graceful shutdown：exit 0
服务日志 email/refresh token/code 扫描：0 matches

仍待执行：新鲜码 HTTP 200、成功响应 rotation、显式未读状态前后对照、paced 100-cycle/soak
```

## Phase 1～5 保留边界

1. 仓库已完成 Go-only 收口，但新鲜 Outlook 码、未读保持、真实 VPS/Caddy 和消费项目部署验收仍未完成；
2. 正式 Outlook Provider 不得退回复制 Phase 0 throwaway 实现；
3. 不持久化任何 TOTP Secret、Outlook/FlySMS credential、邮件或验证码；
4. 不跨请求缓存 TOTP 结果、OAuth access/refresh token、IMAP session、Graph message ID或polling state；
5. 不开启 CORS、UI、docs、pprof 或公网 listener；
6. 回滚只使用前一个已校验的 Go static binary/checksum/SBOM，不再保留第二套服务实现。
