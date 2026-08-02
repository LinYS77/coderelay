# Phase 0 验证记录

更新时间：2026-08-02

## 总状态

```text
Phase 0: PASS
Local controlled gate: PASS
Real Outlook gate: PASS
```

## A. 可重复本地门禁

- [x] OAuth refresh 请求格式和响应上限；
- [x] 自定义 XOAUTH2 SASL client；
- [x] direct TLS + greeting/capability；
- [x] readonly Select 与 `NumMessages`；
- [x] single batch partial sequence `BODY.PEEK` FETCH；
- [x] 流式 UID/INTERNALDATE/body 处理；
- [x] MIME plain/html/attachment 处理；
- [x] 同一 session 的 NOOP 复用；
- [x] `\\Seen` 保持；
- [x] context cancel 中断 blocked FETCH；
- [x] oversized literal 关闭连接并有界退出；
- [x] 100 次连接/关闭无 goroutine/FD 增长；
- [x] `go test -race`；
- [x] `go vet`；
- [x] Go 1.25.12 / 1.26.5 compatibility；
- [x] `govulncheck` 无可达漏洞；
- [x] `CGO_ENABLED=0` build；
- [x] 输出敏感信息扫描。

本地观测（Go 1.26.5）：

```text
blocked FETCH cancellation: < 1 ms
100 connection cycles: goroutines 3 → 3 (delta 0)
100 connection cycles: FDs        7 → 7 (delta 0)
go test -race: PASS
govulncheck reachable vulnerabilities: 0
CGO_ENABLED=0 static build: PASS
```

风险发现：beta.8 在应用丢弃尚未消费的 streaming literal 后直接调用 `Client.Close()` 可能等待解码 goroutine。Adapter 已采用“先关闭底层连接，再让当前 literal reader 读到 transport error，最后等待 client 退出”的顺序，并以 oversized-literal 回归测试覆盖。真实 Outlook 不违反 partial 时不会进入该路径；生产化时仍应把该行为锁在 Adapter 内并考虑 vendor 最小补丁。

## B. 真实 Outlook 门禁

- [x] Microsoft OAuth refresh 成功；
- [x] Outlook `AUTH=XOAUTH2` 成功；
- [x] readonly `INBOX` 成功；
- [x] `SelectData.NumMessages` 有效；
- [x] single batch sequence FETCH 可用；
- [x] partial `BODY.PEEK` 可用；
- [x] UID 和 UTC INTERNALDATE 可用；
- [x] MIME 解析至少一封真实邮件；
- [x] 两轮读取复用同一 session，NOOP 成功；
- [x] 测试邮件没有从 unseen 变为 seen；
- [x] context/deadline 路径没有挂死；
- [x] 100 次真实连接/关闭无 goroutine/FD 增长；
- [x] refresh token 轮换已安全交付调用方；
- [x] 测试输出和日志不含 credential/token/body/code。

真实 Outlook 观测：

```text
OAuth refresh / IMAP scope: PASS
Direct TLS: TLS 1.3
XOAUTH2: PASS
readonly INBOX / NumMessages: PASS / 9
request-scoped session: 1
batch BODY.PEEK cycles: 2
NOOP between cycles: 1
UID + INTERNALDATE + MIME: 9/9
Seen preservation: 9/9
100 real connection cycles with 500ms pacing: 100/100
real goroutines: 3 → 3 (delta 0)
real FDs:        6 → 6 (delta 0)
known-secret scan of JSON report: PASS
refresh-token rotation: returned and atomically saved to caller-managed 0600 file
```

诊断记录：第一次无 pacing 的 100 次运行在连续 XOAUTH2 阶段被 Outlook 拒绝；补充迭代观测后，10 次无间隔为 10/10，500ms pacing 的 100 次为 100/100，且 goroutine/FD 均为零增长。结论是实际风险测试需限制认证速率，不应把上游认证节流误判为 go-imap 资源泄漏。

## 结论

**通过。** `go-imap/v2 v2.0.0-beta.8` 在当前真实 Outlook 路径没有发现阻断 Phase 1 的兼容性问题。进入生产实现时必须保留以下 Adapter 边界：

1. `DebugWriter=nil`；
2. direct TLS + context close + capped deadline；
3. streaming literal 必须消费或通过 Adapter 的 transport-close 顺序释放；
4. readonly Select 与 partial `BODY.PEEK`；
5. 真实连接 soak 必须 pacing，不能无间隔制造上游认证风暴；
6. pin、go.sum，并在生产化时评估 vendor 最小补丁。

Phase 1 可以开始，但本原型仍保持在 `prototypes/`，不得直接复制为生产 Provider。
