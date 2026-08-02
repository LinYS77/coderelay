# CodeRelay Go 重写进度

更新时间：2026-08-02

## 总览

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0：真实 Outlook 风险原型 | ✅ PASS | `go-imap/v2 beta.8` 路径通过；细节见 `prototypes/outlook-go/RESULTS.md` |
| Phase 1：基础服务 + TOTP | ✅ PASS | 正式 Go 模块、HTTP 骨架、TOTP 和 20 并发门禁完成 |
| Phase 2：FlySMS | 🟡 实现 PASS | contract/fuzz/fault 与真实 `NO_FRESH_CODE` 通过；等待新鲜真实邮件完成 HTTP 200 门禁 |
| Phase 3：Outlook 正式实现 | ⬜ 未开始 | Phase 2 最后一项真实门禁后进入；Phase 0 原型不得直接复制进生产路径 |
| Phase 4：Extractor parity | ⬜ 未开始 |  |
| Phase 5：并发与安全收口 | ⬜ 未开始 |  |
| Phase 6：真实验收 | ⬜ 未开始 |  |
| Phase 7：切换与回滚 | ⬜ 未开始 |  |

当前生产服务仍为 Python 0.3.0。Go Phase 2 二进制实现 TOTP 和 FlySMS；Outlook 请求仍返回 `422 INVALID_CODE_REQUEST`，不能替换生产服务。

---

## Phase 1～2 交付

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
- [x] graceful shutdown 基础；
- [x] CGO=0 Linux amd64 静态二进制；
- [x] Go 1.25.12 / 1.26.5 CI；
- [x] race、fuzz smoke、staticcheck、govulncheck。

## Phase 1～2 验收结果

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
HTTP status：404
error code：NO_FRESH_CODE
elapsed：1.069 s
credential/code application-log matches：0
```

真实 credential、上游连接和无新鲜码语义已经通过。由于验收时邮箱中没有 10 分钟内的新验证码，真实 `HTTP 200 + six-digit code` 门禁仍需先触发一封新的验证码邮件；合成 contract 的新鲜码路径已返回正确六位 code。

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
```

构建产物（本地、未提交）：

```text
dist/coderelay-go
size: 7,631,010 bytes
SHA-256: 8203cfa0a8a35fb998323464f60f7644535a6446a039a1480300ea8a002e9227
ELF x86-64, statically linked, stripped
```

## Phase 1 保留边界

1. Go Phase 2 不是生产替代品，只支持 TOTP 和 FlySMS，尚无 Outlook；
2. 不实现正式 Outlook Provider；
3. 不复制 Phase 0 throwaway 实现；
4. 不持久化任何 TOTP Secret 或验证码；
5. 不跨请求缓存 TOTP 结果；
6. 不开启 CORS、UI、docs、pprof 或公网 listener；
7. Phase 3 开始前继续保留 Python 0.3.0 生产基线与回滚能力。
