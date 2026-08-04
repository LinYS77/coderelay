# CodeRelay Go API 调用指南

本文档提供给调用 `https://2fa.077.li` 的后端项目。CodeRelay Go 是无状态取码服务：每次请求携带本次上游凭据，服务器不持久化这些凭据。

## 1. 固定契约

```http
POST /api/v1/code
Host: 2fa.077.li
Authorization: Bearer <CODERELAY_API_TOKEN>
Content-Type: application/json
Accept: application/json
```

成功响应：

```json
{"code":"123456"}
```

调用项目正常只需读取：

```python
code = response.json()["code"]
```

所有取码请求必须有 CodeRelay Bearer Token。Token 只允许放在 `Authorization` 请求头，不接受 URL/query token。

## 2. 两层凭据

一次调用包含两类不同凭据：

1. **CodeRelay API Token**：证明调用项目有权使用公网服务；
2. **请求级 credential**：本次 TOTP、Outlook 或 FlySMS 上游凭据。

CodeRelay 服务器只持久化第 1 类凭据的 hash。第 2 类凭据仅在请求期间存在于内存中，不写配置、文件、数据库或跨请求缓存。

本部署中的两个受控消费项目可以共用同一枚 API Token：

```text
CODERELAY_BASE_URL=https://2fa.077.li
CODERELAY_API_TOKEN=<管理员签发的共享Token>
```

共享不会导致请求级 Outlook/FlySMS/TOTP credential 串用，但意味着两个项目共享：

- 每 Token `240/minute`、burst `40` 的 token bucket；
- 最多 20 active + 4 queued、queue wait 2 秒的服务 admission；
- Token撤销故障域；
- Token轮换窗口；
- 单项目审计区分能力。

CodeRelay 还按来源 IP 应用独立 token bucket，且两类限流状态都有硬容量上限。第 25 个同时到达的取码请求不会进入无界队列，而会在 `<100 ms` 内返回 `503 SERVER_BUSY`；被 admission、鉴权或限流拒绝的 credential body 不会被读取。

因此轮换时必须协调更新两个项目。若未来需要独立撤销或独立限流，再改成每项目一枚Token。

不要把 API Token 或请求级 credential 写入：

- URL；
- Git；
- 普通日志；
- 异常信息；
- 监控标签；
- 浏览器前端；
- 消息队列的明文事件。

## 3. TOTP

请求：

```json
{
  "type": "totp",
  "credential": "BASE32_SECRET",
  "min_ttl": 5
}
```

`credential` 支持：

- Base32 TOTP Secret；
- 完整 `otpauth://totp/...` URI。

约束：

- 只返回六位 TOTP；
- `min_ttl` 范围 0～30，推荐 5；
- 当前窗口剩余时间不足时，服务等待下一个窗口。

## 4. Outlook

请求：

```json
{
  "type": "outlook",
  "credential": "email----password----client_id----refresh_token",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

处理方式：

```text
解析四段式
→ password 立即丢弃
→ refresh token 换取 access token
→ IMAP XOAUTH2
→ readonly 选择 INBOX
→ BODY.PEEK 读取，不标记已读
→ 提取六位验证码
→ 请求结束清理引用
```

CodeRelay 不使用 Outlook password；保留该字段只是为了兼容调用项目现有字符串格式。

### Refresh token 轮换

Microsoft 可能在刷新 access token 时返回新的 refresh token。CodeRelay 不保存它，而是返回给调用项目：

```json
{
  "code": "123456",
  "credential_update": {
    "refresh_token": "NEW_REFRESH_TOKEN"
  }
}
```

调用项目必须原子更新自己的 secret manager 中第四段 refresh token。

即使没有新验证码，错误响应也可能携带轮换信息：

```json
{
  "error": {
    "code": "NO_FRESH_CODE",
    "message": "No matching fresh verification code was found",
    "retryable": true,
    "retry_after_seconds": 2,
    "request_id": "..."
  },
  "credential_update": {
    "refresh_token": "NEW_REFRESH_TOKEN"
  }
}
```

因此调用方必须先处理 `credential_update`，再处理成功或错误。

## 5. FlySMS

请求 credential 格式：

```text
email---token---https://flysms.xyz/icloud/pickup#email=...&key=...
```

JSON：

```json
{
  "type": "flysms",
  "credential": "email---token---https://flysms.xyz/icloud/pickup#email=...&key=...",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

CodeRelay 会验证：

- 第一段 email 格式；
- 第二段 `tok_...` 格式；
- URL 必须是 `https://flysms.xyz/icloud/pickup`；
- fragment 必须且只能含 `email` 和 `key`；
- fragment 的 email/token 必须与前两段一致；
- 不允许调用项目改变协议、域名、端口或路径。

传入的 pickup URL 只用于格式和一致性验证。CodeRelay 实际请求固定的 FlySMS JSON API，不会把它当作任意 URL 请求，从而避免 SSRF。

FlySMS 上游冷同步可能较慢，调用方必须正确处理 `502`、`503` 和 `504`。

## 6. `not_before` 与正确性

邮件验证码建议始终传 `not_before`：

```text
1. 调用项目记录当前 UTC 时间
2. 调用项目触发上游发送验证码
3. 将记录时间传给 CodeRelay
```

Python：

```python
async def request_current_code(credential: str) -> str:
    triggered_at = datetime.now(UTC)
    await trigger_remote_verification_email()
    code, credential_update = await resolve_code(
        type="outlook",
        credential=credential,
        not_before=triggered_at,
    )
    if credential_update is not None:
        await persist_refresh_token_atomically(credential_update["refresh_token"])
    return code
```

`not_before` 必须包含时区，推荐 UTC `Z` 格式。调用方和 VPS 都应启用 NTP。

如果省略，CodeRelay 仍会应用服务器配置的最大邮件年龄，但无法严格区分本次验证码和很近的上一封验证码。

## 7. `wait_seconds` 与客户端超时

邮件请求：

```text
wait_seconds：0～30，推荐 30
连接超时：5 秒
调用方整体超时：90 秒
```

已经开始的上游读取使用独立硬超时，不会被较短的轮询窗口中途截断，因此实际 HTTP 时长可能略超过 `wait_seconds`。

不要在调用项目中每秒高频轮询。优先使用一次 `wait_seconds=30` 请求。

## 8. Python 异步消费端示例

以下只是外部调用项目示例，不是 CodeRelay 服务实现；仓库中的服务端仅保留 Go。

依赖：

```bash
pip install httpx
```

```python
from __future__ import annotations

import os
from datetime import UTC, datetime
from typing import Any

import httpx

BASE_URL = os.environ.get("CODERELAY_BASE_URL", "https://2fa.077.li").rstrip("/")
API_TOKEN = os.environ["CODERELAY_API_TOKEN"]


class CodeRelayError(RuntimeError):
    def __init__(self, *, status: int, payload: dict[str, Any]) -> None:
        error = payload.get("error", {})
        self.status = status
        self.code = str(error.get("code", "UNKNOWN_ERROR"))
        self.retryable = bool(error.get("retryable", False))
        self.retry_after_seconds = error.get("retry_after_seconds")
        self.credential_update = payload.get("credential_update")
        super().__init__(self.code)


async def resolve_code(
    *,
    type: str,
    credential: str,
    not_before: datetime | None = None,
    wait_seconds: int = 30,
    min_ttl: int = 5,
) -> tuple[str, dict[str, str] | None]:
    body: dict[str, Any] = {"type": type, "credential": credential}
    if type == "totp":
        body["min_ttl"] = min_ttl
    else:
        body["wait_seconds"] = wait_seconds
        if not_before is not None:
            if not_before.tzinfo is None:
                raise ValueError("not_before must include a timezone")
            body["not_before"] = not_before.astimezone(UTC).isoformat().replace("+00:00", "Z")

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(90.0, connect=5.0),
        follow_redirects=False,
    ) as client:
        response = await client.post(
            f"{BASE_URL}/api/v1/code",
            json=body,
            headers={
                "Authorization": f"Bearer {API_TOKEN}",
                "Accept": "application/json",
            },
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise RuntimeError(f"CodeRelay returned non-JSON HTTP {response.status_code}") from exc

    # 即使失败也可能需要持久化 Outlook token 轮换。
    credential_update = payload.get("credential_update") if isinstance(payload, dict) else None
    if response.status_code != 200:
        raise CodeRelayError(status=response.status_code, payload=payload)

    code = payload.get("code")
    if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
        raise RuntimeError("CodeRelay returned an invalid success payload")
    return code, credential_update
```

调用项目在收到 `credential_update` 后，应先完成原子 secret 更新，再继续后续业务。

禁止：

```python
logger.info(response.text)
logger.info(body)
print(credential)
```

日志只记录 HTTP 状态、错误码、`request_id` 和耗时。

## 9. Node.js 20+ 客户端

```javascript
const baseUrl = (process.env.CODERELAY_BASE_URL ?? "https://2fa.077.li").replace(/\/$/, "");
const apiToken = process.env.CODERELAY_API_TOKEN;

export async function resolveCode(body) {
  if (!apiToken) throw new Error("CODERELAY_API_TOKEN is required");

  const response = await fetch(`${baseUrl}/api/v1/code`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      Accept: "application/json",
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
    redirect: "error",
    signal: AbortSignal.timeout(90_000),
  });

  const payload = await response.json();
  const credentialUpdate = payload?.credential_update ?? null;

  if (!response.ok) {
    const error = new Error(payload?.error?.code ?? `HTTP_${response.status}`);
    error.statusCode = response.status;
    error.code = payload?.error?.code;
    error.retryable = payload?.error?.retryable === true;
    error.retryAfterSeconds = payload?.error?.retry_after_seconds ?? null;
    error.credentialUpdate = credentialUpdate;
    throw error;
  }

  if (!/^\d{6}$/.test(payload.code)) {
    throw new Error("CodeRelay returned an invalid success payload");
  }
  return { code: payload.code, credentialUpdate };
}
```

此代码只能运行在受控后端，不能把 CodeRelay Token 或上游 credential 下发给浏览器。

## 10. 错误处理

统一错误主体：

```json
{
  "error": {
    "code": "NO_FRESH_CODE",
    "message": "No matching fresh verification code was found",
    "retryable": true,
    "retry_after_seconds": 2,
    "request_id": "0123456789abcdef01234567"
  }
}
```

| HTTP | 错误码 | 行为 |
|---:|---|---|
| 401 | `AUTHENTICATION_REQUIRED` | 不重试；检查 CodeRelay Token |
| 404 | `NO_FRESH_CODE` | 可按 `retry_after_seconds` 有限重试 |
| 409 | `AMBIGUOUS_CODE` | 不要随机选码；联系管理员调整规则 |
| 422 | `VALIDATION_ERROR` / `INVALID_CODE_REQUEST` | 不重试；修正 JSON 或 credential 格式 |
| 424 | `SOURCE_CREDENTIALS_INVALID` | 不重试；检查请求中的 client ID/refresh token，并由管理员按 request ID 查看安全 `source_stage` |
| 424 | `SOURCE_REAUTH_REQUIRED` | 不重试；重新获得 Outlook refresh token |
| 424 | `SOURCE_EXPIRED_OR_DISABLED` | 不重试；检查 FlySMS 权益 |
| 429 | `RATE_LIMITED` / `SOURCE_RATE_LIMITED` | 尊重 `Retry-After` |
| 502 | `UPSTREAM_FAILURE` | 有限指数退避 |
| 502 | `UPSTREAM_SCHEMA_CHANGED` | 不盲目重试；通知维护者 |
| 503 | `SERVER_BUSY` | admission 已满；尊重 `Retry-After`，只做有限抖动退避 |
| 503 | `SOURCE_SYNCING` | 按 `Retry-After` 重试 |
| 504 | `UPSTREAM_TIMEOUT` | 有限指数退避 |

任何响应都应先处理可选 `credential_update`。

Outlook credential 错误不会把上游错误正文返回给调用方。管理员可以用响应的 `request_id` 查询 CodeRelay 结构化日志中的固定 `source_stage`：

```text
outlook_oauth_token  Microsoft token endpoint 拒绝 refresh 请求
outlook_oauth_scope  OAuth 返回的授权范围不含 IMAP scope
outlook_imap_auth    Outlook IMAP 拒绝 XOAUTH2 token
```

这些字段不包含 email、token 或 credential。不得通过开启请求 body 日志或 IMAP `DebugWriter` 进行诊断。

推荐最多重试 2～3 次。对 `SERVER_BUSY` 使用 `Retry-After` 加随机抖动，且总时长仍受 90 秒调用方 deadline 限制；不要无限重试 401、409、422、424 或任何 503。

## 11. 响应与日志安全

所有 API 响应包含：

```http
Cache-Control: no-store, private
Pragma: no-cache
X-Content-Type-Options: nosniff
```

调用项目必须：

- 禁止缓存成功响应；
- 禁止记录请求 body；
- 禁止记录成功 response body；
- 禁止在错误日志中序列化异常附带的 `credential_update`；
- 禁止将验证码用于指标 label；
- 只在业务所需的最短时间内保留验证码。

## 12. 管理员签发共享 Token

本部署只需签发一枚供两个受控项目共用的 Token：

```bash
sudo -u coderelay /usr/local/bin/coderelay \
  generate-api-token \
  --hash-file /etc/coderelay/secrets/api-shared.sha256
```

配置：

```toml
[security]
api_token_hash_files = [
  "/etc/coderelay/secrets/api-shared.sha256",
]
```

轮换步骤：

```text
1. 生成新共享Token和新hash文件
2. 配置同时加载新旧两个hash并重启CodeRelay
3. 更新项目A并验证
4. 更新项目B并验证
5. 删除旧hash
6. 再次重启
```

在两个项目都验证新Token前不得删除旧hash。共享Token必须进入两个项目各自的secret manager，不能进入代码仓库或普通配置。

## 13. 上线验收

从真实消费项目所在机器验证：

1. 无 Token 的 POST 返回 401；
2. URL 中携带 Token 仍返回 401；
3. 正确 Bearer + TOTP 请求返回仅含 `code` 的 200 JSON；
4. Outlook/FlySMS credential 只放 POST JSON body；
5. `not_before` 可以阻止旧码；
6. Outlook 轮换 token 能被调用项目原子保存；
7. CodeRelay 重启后不存在任何上游 credential 文件；
8. 服务日志、Caddy 日志和消费项目日志均无请求 body、验证码和 token；
9. 响应包含 `Cache-Control: no-store`；
10. VPS 只公开 443，不公开 8787。
