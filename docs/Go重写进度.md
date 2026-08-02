# CodeRelay Go 重写进度

更新时间：2026-08-02

## 总览

| Phase | 状态 | 说明 |
|---|---|---|
| Phase 0：真实 Outlook 风险原型 | ✅ PASS | `go-imap/v2 beta.8` 路径通过；细节见 `prototypes/outlook-go/RESULTS.md` |
| Phase 1：基础服务 + TOTP | ✅ PASS | 正式 Go 模块、HTTP 骨架、TOTP 和 20 并发门禁完成 |
| Phase 2：FlySMS | ⬜ 未开始 | 下一阶段 |
| Phase 3：Outlook 正式实现 | ⬜ 未开始 | Phase 0 原型不得直接复制进生产路径 |
| Phase 4：Extractor parity | ⬜ 未开始 |  |
| Phase 5：并发与安全收口 | ⬜ 未开始 |  |
| Phase 6：真实验收 | ⬜ 未开始 |  |
| Phase 7：切换与回滚 | ⬜ 未开始 |  |

当前生产服务仍为 Python 0.3.0。Go Phase 1 二进制只实现 TOTP；Outlook/FlySMS 请求暂时返回 `422 INVALID_CODE_REQUEST`，不能替换生产服务。

---

## Phase 1 交付

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
- [x] request-scoped Secret、best-effort clear、日志/序列化脱敏；
- [x] graceful shutdown 基础；
- [x] CGO=0 Linux amd64 静态二进制；
- [x] Go 1.25.12 / 1.26.5 CI；
- [x] race、fuzz smoke、staticcheck、govulncheck。

## Phase 1 验收结果

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
Go tests: 63 passed / 12 packages
go test -race: PASS
FuzzDecodeRootObject smoke: PASS
FuzzCredentialParser smoke: PASS
staticcheck v0.7.0: PASS
govulncheck reachable vulnerabilities: 0
Python regression: 64 passed
```

构建产物（本地、未提交）：

```text
dist/coderelay-go
size: 6,926,498 bytes
SHA-256: 5e7fda1381c1e476b0028e16784726c2050f27e0aa09172d372bfa7e6d888251
ELF x86-64, statically linked, stripped
```

## Phase 1 保留边界

1. Go Phase 1 不是生产替代品，只支持 TOTP；
2. 不实现 Outlook/FlySMS Provider；
3. 不复制 Phase 0 throwaway 实现；
4. 不持久化任何 TOTP Secret 或验证码；
5. 不跨请求缓存 TOTP 结果；
6. 不开启 CORS、UI、docs、pprof 或公网 listener；
7. Phase 2 开始前继续保留 Python 0.3.0 生产基线与回滚能力。
