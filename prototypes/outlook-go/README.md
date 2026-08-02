# Outlook Go Phase 0 风险原型

> **PROTOTYPE / THROWAWAY**：这里不是 CodeRelay Go 正式实现，也不会被正式服务导入或运行。
>
> **结论：PASS（2026-08-02）**。本地受控门禁和真实 Outlook 门禁均已通过；详细证据见 [`RESULTS.md`](RESULTS.md)。

## 要回答的问题

`github.com/emersion/go-imap/v2 v2.0.0-beta.8` 能否在真实 Outlook 上同时满足：

1. Microsoft refresh-token OAuth；
2. XOAUTH2；
3. readonly `INBOX`；
4. `SelectData.NumMessages`；
5. 最近 N 封邮件的单次批量、流式、partial `BODY.PEEK` FETCH；
6. UID、`INTERNALDATE` 和 MIME 解析；
7. 同一请求内通过 `NOOP` 复用同一 IMAP session；
8. context cancel/timeout 能通过关闭底层连接中断阻塞操作；
9. 100 次连接/关闭后没有 goroutine 或 FD 增长；
10. 不把 credential、OAuth token、邮件正文或验证码写入输出。

Phase 0 只回答技术风险，不提供 CodeRelay HTTP API、提取器、限流或生产配置。

## 固定依赖

```text
Go language version:                 1.25.0
Real-probe/default build toolchain:  Go 1.26.5 or later security patch
Compatibility test toolchain:        Go 1.25.12 or later security patch
github.com/emersion/go-imap/v2:      v2.0.0-beta.8
github.com/emersion/go-message:      v0.18.2
github.com/emersion/go-sasl:         pinned pseudo-version
```

本机旧工具链 Go 1.25.10 和基础 Go 1.26.0 均命中已修复的标准库安全公告，因此真实 credential 探针默认强制使用 `go1.26.5`。`imapclient.Options.DebugWriter` 始终为 `nil`。

## 一条命令运行本地门禁

```bash
./prototypes/outlook-go/scripts/verify.sh
```

它执行：

- `gofmt` 检查；
- `go vet`；
- 本地 TLS OAuth/IMAP 风险测试；
- context cancellation 测试；
- 100 次连接/关闭资源测试；
- `go test -race`；
- `govulncheck` 可达漏洞扫描；
- `CGO_ENABLED=0` 静态构建。

本地测试使用内存邮箱和本地 TLS server，不访问 Microsoft，也不需要真实 credential。

## 真实 Outlook 门禁

### 1. 准备受限 credential 文件

文件内容保持兼容格式：

```text
email----password----client_id----refresh_token
```

设置权限：

```bash
chmod 600 /安全路径/outlook-phase0.secret
```

不要把文件放入 Git，也不要在命令行直接传 credential。原型拒绝符号链接、非普通文件、非当前用户所有或 group/world 可读写的 credential 文件。

### 2. 运行真实探针

```bash
./prototypes/outlook-go/scripts/run-real.sh \
  --credential-file /安全路径/outlook-phase0.secret \
  --rotation-output /安全路径/outlook-rotated-refresh-token.secret
```

默认在一个请求级 session 中执行两轮批量 FETCH，中间发送一次 `NOOP`。输出只包含：

- OAuth/IMAP 阶段是否成功；
- TLS 版本；
- Inbox 邮件数；
- sequence、UID 和 UTC `INTERNALDATE`；
- MIME part/字节计数；
- `\\Seen` 是否保持；
- FETCH/NOOP/session 数量；
- goroutine/FD 差值。

不会输出 email、client ID、access token、refresh token、subject、sender、正文或验证码。

Microsoft 若返回轮换 refresh token，原型会在开始 IMAP 前将它原子写入 `--rotation-output`，权限固定为 `0600`。该文件属于调用者管理的测试 secret，不是 CodeRelay 服务端状态。只有输出中的 `rotation_returned` 和 `rotation_saved` 同时为 `true` 时，该文件才代表本轮新 token；完成验收后必须把它更新到调用项目的 secret manager，并安全删除测试文件。

### 3. 真实 100 次连接/关闭门禁

先完成单次探针，再单独运行：

```bash
./prototypes/outlook-go/scripts/run-real.sh \
  --credential-file /安全路径/outlook-phase0.secret \
  --rotation-output /安全路径/outlook-rotated-refresh-token.secret \
  --leak-iterations 100 \
  --leak-delay 500ms \
  --overall-timeout 20m
```

真实探针默认对每次资源循环使用 500ms pacing，避免把 Outlook 认证节流误判为本地泄漏。第一次无 pacing 的长循环曾被上游拒绝；500ms pacing 的真实 100 次测试为 100/100。可以在受控本地 mock 中使用零间隔，但不要对真实 Outlook 制造无间隔认证风暴。

这 100 次只执行 direct TLS、XOAUTH2、readonly Select、NOOP 和关闭，不重复读取邮件正文，也只进行一次 OAuth refresh。若 Microsoft 限流，该项记录完成迭代数并失败，不进行无界重试。

## 安全边界

- OAuth endpoint 固定为 Microsoft `common/oauth2/v2.0/token`；
- IMAP 固定为 `outlook.office365.com:993`；
- TLS 最低 1.2，验证系统 CA 和 SNI；
- 不使用环境 HTTP proxy；
- OAuth 禁止 redirect；
- token response 最大 1 MiB；
- IMAP literal 最大 256 KiB；
- 每轮最多读取最近 10 封；
- 所有 IMAP 操作受 context、连接关闭和 deadline 共同约束；
- LOGOUT 最多占用 1 秒，之后强制关闭连接；
- secret byte slice 在可控范围内 best-effort `clear`；Go string/运行时副本不能承诺物理清零。

## 已发现的 beta.8 边界

如果服务器违反 partial 请求并声明超大 streaming literal，应用在不消费 reader 的情况下直接调用 `imapclient.Client.Close()`，beta.8 可能等待解码 goroutine。原型 Adapter 的处理顺序为：

```text
检测 literal.Size 超限
→ 立即关闭底层 net.Conn
→ 让当前 literal reader 读到 transport error，释放库内部 done channel
→ 再等待 client decoder 退出
```

该路径已有本地 TLS 回归测试。它是 go-imap 细节，不允许泄露到后续 domain/service；正式实现前应评估 vendor 最小补丁，使取消动作成为显式 Adapter 能力。

## 状态记录

见 [`RESULTS.md`](RESULTS.md)。只有本地门禁和真实 Outlook 门禁全部通过，Phase 0 才能标记完成。
