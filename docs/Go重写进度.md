# CodeRelay Go 重写进度

更新时间：2026-08-02

## 总览

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0：真实 Outlook 风险原型 | ✅ PASS | `go-imap/v2 beta.8` 路径通过；细节见 `prototypes/outlook-go/RESULTS.md` |
| Phase 1：基础服务 + TOTP | ✅ PASS | 正式 Go 模块、HTTP 骨架、TOTP 和 20 并发门禁完成 |
| Phase 2：FlySMS | ✅ PASS | contract/fuzz/fault、真实 `NO_FRESH_CODE` 和真实 HTTP 200 六位码均通过 |
| Phase 3：Outlook 正式实现 | 🟡 实现中 | 正式 Provider 与本地 hardening 已完成；真实 OAuth/XOAUTH2/IMAP、`NO_FRESH_CODE` 错误轮换交付通过，新鲜码/未读保持/soak 仍待完成 |
| Phase 4：Extractor parity | ⬜ 未开始 |  |
| Phase 5：并发与安全收口 | ⬜ 未开始 |  |
| Phase 6：真实验收 | ⬜ 未开始 |  |
| Phase 7：切换与回滚 | ⬜ 未开始 |  |

当前生产服务仍为 Python 0.3.0。Go Phase 3 已通过一次正式二进制的真实 OAuth、IMAP 和错误响应轮换门禁，但尚未完成新鲜码 HTTP 200、显式未读状态对照和资源 soak，不能替换生产服务。

---

## Phase 1～3 交付（Phase 3 实现阶段）

正式代码位于：

```text
cmd/coderelay/
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
config.go.example.toml
scripts/build-go.sh
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
- [x] UID/InternalDate、单次批量 streaming `BODY.PEEK` partial FETCH、bounded MIME 解析；
- [x] 成功与业务错误响应的 `credential_update` 传播；
- [x] graceful shutdown 基础；
- [x] CGO=0 Linux amd64 静态二进制；
- [x] Go 1.25.12 / 1.26.5 CI；
- [x] race、fuzz smoke、staticcheck、govulncheck。

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
Python regression: 64 passed
CI: https://github.com/LinYS77/coderelay/actions/runs/30733137080 (success)
```

构建产物（本地、未提交）：

```text
dist/coderelay-go
size: 7,631,010 bytes
SHA-256: 8203cfa0a8a35fb998323464f60f7644535a6446a039a1480300ea8a002e9227
ELF x86-64, statically linked, stripped
```

## Phase 3 当前验证

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

## Phase 1～3 保留边界

1. Go Phase 3 尚未成为生产替代品；新鲜 Outlook 码、未读保持、Extractor parity、并发 soak 和部署验收仍未完成；
2. 正式 Outlook Provider 不得退回复制 Phase 0 throwaway 实现；
3. 不持久化任何 TOTP Secret、Outlook/FlySMS credential、邮件或验证码；
4. 不跨请求缓存 TOTP 结果、OAuth access/refresh token 或 IMAP session；
5. 不开启 CORS、UI、docs、pprof 或公网 listener；
6. 继续保留 Python 0.3.0 生产基线与回滚能力。
