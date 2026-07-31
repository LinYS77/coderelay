# CodeRelay API 调用指南

本文档提供给需要从 CodeRelay 获取验证码的其他项目。

## 1. 服务地址与安全要求

生产地址：

```text
https://2fa.077.li
```

所有读取来源或验证码的 API 都需要鉴权：

```http
Authorization: Bearer <CODERELAY_API_TOKEN>
```

调用方必须遵守：

- 只使用 HTTPS，不允许绕过 HTTPS 调用公网服务；
- API Token 只能放在 `Authorization` 请求头；
- 禁止把 Token 放入 URL、查询参数、源码、Git、异常信息或普通日志；
- 禁止记录完整验证码响应；
- Token 应由部署平台的 secret/environment 管理；
- 每个消费项目使用独立 Token，避免多个项目共享同一把密钥；
- 收到 `401` 后不要无限重试，应检查或轮换 Token；
- 所有 API 尝试（包括无效 Token）受每 IP 限流，已认证调用还受每 Token 指纹限流；默认上限为每分钟 60 次。

推荐环境变量：

```text
CODERELAY_BASE_URL=https://2fa.077.li
CODERELAY_API_TOKEN=<由管理员单独签发>
```

以下端点不需要 API Token，但不会返回来源、邮箱或验证码：

```text
GET /health/live
GET /health/ready
```

网页密码/session 与机器 API Token 是两套独立凭据。其他项目必须使用 Bearer Token，不应模拟网页登录。

## 2. 最小调用流程

邮件验证码的可靠调用流程是：

```text
1. 记录当前 UTC 时间
2. 触发目标系统发送验证码邮件
3. 调用 CodeRelay，并将第 1 步的时间作为 not_before
4. 从 HTTP 200 JSON 响应读取 code
```

不能简单地无条件获取“最后一封邮件”，否则可能把上一次验证码误认为当前验证码。

示意：

```python
async def request_current_code() -> str:
    triggered_at = datetime.now(UTC)  # 必须在触发发送之前记录
    await trigger_remote_verification_email()
    return await get_coderelay_code(
        source_id="outlook_primary",
        not_before=triggered_at,
    )
```

调用方和 CodeRelay VPS 都应启用 NTP 时间同步。

## 3. API 概览

### 3.1 查询可用来源

```http
GET /api/v1/sources
Authorization: Bearer <token>
```

示例：

```bash
curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 30 \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Accept: application/json" \
  https://2fa.077.li/api/v1/sources
```

成功响应示例：

```json
[
  {
    "id": "primary_totp",
    "display_name": "Primary TOTP",
    "provider_type": "totp",
    "kind": "totp",
    "state": "ready",
    "experimental": false,
    "identity_hint": null
  },
  {
    "id": "outlook_primary",
    "display_name": "Outlook",
    "provider_type": "outlook_imap",
    "kind": "email",
    "state": "ready",
    "experimental": false,
    "identity_hint": "a***z@example.com"
  }
]
```

调用项目通常应固定使用管理员分配的 `source_id`，而不是每次根据 `display_name` 猜测来源。

### 3.2 获取验证码

```http
GET /api/v1/codes/{source_id}
Authorization: Bearer <token>
```

成功响应中的 `code` 始终为六位数字字符串：

```json
{
  "source_id": "outlook_primary",
  "kind": "email",
  "code": "123456",
  "freshness": "fresh",
  "observed_at": "2026-07-30T09:05:00Z",
  "received_at": "2026-07-30T09:04:28Z",
  "valid_from": null,
  "expires_at": null,
  "remaining_seconds": null,
  "evidence": {
    "sender": "Service <no-reply@example.com>",
    "subject": "Your verification code ••••••",
    "message_fingerprint": "sha256:0123456789abcdef01234567"
  }
}
```

调用方正常情况下只需要：

```python
code = response.json()["code"]
```

不要依赖 `evidence.subject` 的具体文本；它只用于诊断，并可能随邮件模板变化。

所有验证码响应都包含：

```http
Cache-Control: no-store, private
Pragma: no-cache
```

调用方也不得自行缓存验证码。

## 4. 请求参数

### `not_before`

适用：Outlook、FlySMS 等邮件来源。

RFC 3339/ISO 8601 格式，必须包含时区。推荐传 UTC：

```text
2026-07-30T09:03:00Z
```

含义：只接受该时间点之后收到的邮件。

邮件来源在生产调用中应始终传此参数。

### `wait_seconds`

适用：邮件来源。

```text
范围：0～30 秒（受服务器配置限制）
推荐：30
```

没有匹配邮件时，CodeRelay 会在有限时间内重新检查。已经开始的上游读取拥有独立的硬超时，不会被过短的 `wait_seconds` 截断，因此实际 HTTP 请求时间可能略高于该值。

调用项目推荐设置：

```text
连接超时：5 秒
整体请求超时：75 秒
```

不要使用两秒之类的客户端整体超时。

### `min_ttl`

适用：TOTP。

表示返回的 TOTP 至少还需要有效多少秒：

```text
范围：0～30
推荐：5
```

如果当前验证码即将过期，CodeRelay 会等待下一时间窗口后再返回。

## 5. 各来源调用示例

### 5.1 TOTP

```bash
curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 40 \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Accept: application/json" \
  'https://2fa.077.li/api/v1/codes/primary_totp?min_ttl=5'
```

### 5.2 Outlook 邮件验证码

先记录触发时间，再触发发送邮件：

```bash
NOT_BEFORE=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
# 在这里触发目标服务发送验证码
```

调用：

```bash
curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 75 \
  --get \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Accept: application/json" \
  --data-urlencode "not_before=${NOT_BEFORE}" \
  --data-urlencode "wait_seconds=30" \
  'https://2fa.077.li/api/v1/codes/outlook_primary'
```

### 5.3 FlySMS

```bash
curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 75 \
  --get \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Accept: application/json" \
  --data-urlencode "not_before=${NOT_BEFORE}" \
  --data-urlencode "wait_seconds=30" \
  'https://2fa.077.li/api/v1/codes/icloud_pickup'
```

FlySMS 来源标记为 `experimental`。其上游冷同步可能较慢或暂时不可用，调用方必须正确处理 `502`、`503` 和 `504`，不能把上游失败当作“验证码为空”。

## 6. Python 异步客户端示例

依赖：

```bash
pip install httpx
```

```python
from __future__ import annotations

import os
from datetime import UTC, datetime

import httpx

BASE_URL = os.environ.get("CODERELAY_BASE_URL", "https://2fa.077.li").rstrip("/")
API_TOKEN = os.environ["CODERELAY_API_TOKEN"]


class CodeRelayError(RuntimeError):
    def __init__(
        self,
        code: str,
        message: str,
        *,
        status_code: int,
        retryable: bool,
        retry_after_seconds: int | None,
    ) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.status_code = status_code
        self.retryable = retryable
        self.retry_after_seconds = retry_after_seconds


async def get_code(
    source_id: str,
    *,
    not_before: datetime | None = None,
    wait_seconds: int = 30,
    min_ttl: int = 5,
) -> str:
    params: dict[str, str | int] = {
        "wait_seconds": wait_seconds,
        "min_ttl": min_ttl,
    }
    if not_before is not None:
        if not_before.tzinfo is None:
            raise ValueError("not_before must be timezone-aware")
        params["not_before"] = not_before.astimezone(UTC).isoformat().replace("+00:00", "Z")

    timeout = httpx.Timeout(75.0, connect=5.0)
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
        response = await client.get(
            f"{BASE_URL}/api/v1/codes/{source_id}",
            params=params,
            headers={
                "Authorization": f"Bearer {API_TOKEN}",
                "Accept": "application/json",
            },
        )

    payload = response.json()
    if response.status_code == 200:
        code = payload.get("code")
        if not isinstance(code, str) or len(code) != 6 or not code.isdigit():
            raise RuntimeError("CodeRelay returned an invalid success payload")
        return code

    error = payload.get("error", {}) if isinstance(payload, dict) else {}
    raise CodeRelayError(
        str(error.get("code", "UNKNOWN_ERROR")),
        str(error.get("message", "CodeRelay request failed")),
        status_code=response.status_code,
        retryable=bool(error.get("retryable", False)),
        retry_after_seconds=error.get("retry_after_seconds"),
    )


async def example() -> str:
    # 必须先记录时间，再触发发送验证码。
    triggered_at = datetime.now(UTC)
    await trigger_remote_verification_email()
    return await get_code(
        "outlook_primary",
        not_before=triggered_at,
        wait_seconds=30,
    )
```

安全要求：不要用 `logger.info(payload)`、`print(response.text)` 等方式记录成功响应。

## 7. JavaScript / TypeScript 示例

适用于 Node.js 20+：

```javascript
const baseUrl = (process.env.CODERELAY_BASE_URL ?? "https://2fa.077.li").replace(/\/$/, "");
const apiToken = process.env.CODERELAY_API_TOKEN;

if (!apiToken) {
  throw new Error("CODERELAY_API_TOKEN is required");
}

export async function getCode(sourceId, { notBefore, waitSeconds = 30, minTtl = 5 } = {}) {
  const url = new URL(`/api/v1/codes/${encodeURIComponent(sourceId)}`, baseUrl);
  url.searchParams.set("wait_seconds", String(waitSeconds));
  url.searchParams.set("min_ttl", String(minTtl));
  if (notBefore) {
    url.searchParams.set("not_before", notBefore.toISOString());
  }

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${apiToken}`,
      Accept: "application/json",
    },
    redirect: "error",
    signal: AbortSignal.timeout(75_000),
  });

  const payload = await response.json();
  if (response.ok) {
    if (!/^\d{6}$/.test(payload.code)) {
      throw new Error("CodeRelay returned an invalid success payload");
    }
    return payload.code;
  }

  const error = new Error(payload?.error?.code ?? `HTTP_${response.status}`);
  error.statusCode = response.status;
  error.code = payload?.error?.code;
  error.retryable = payload?.error?.retryable === true;
  error.retryAfterSeconds = payload?.error?.retry_after_seconds ?? null;
  throw error;
}
```

服务端项目不得把 API Token 下发给浏览器。上述代码应运行在受控的后端进程中。

## 8. 错误处理

统一错误响应：

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

| HTTP | 错误码 | 调用方行为 |
|---:|---|---|
| 401 | `AUTHENTICATION_REQUIRED` | 不自动重试；检查 Token、域名和 Authorization 头 |
| 404 | `NO_FRESH_CODE` | 可按 `retry_after_seconds` 有限重试 |
| 404 | `SOURCE_NOT_FOUND` / `SOURCE_DISABLED` | 不重试；检查 source ID 或联系管理员 |
| 409 | `AMBIGUOUS_CODE` | 不要随机选码；联系管理员调整提取规则 |
| 422 | `VALIDATION_ERROR` / `HTTP_ERROR` | 不重试；修正请求参数 |
| 424 | `SOURCE_CREDENTIALS_INVALID` | 不重试；通知管理员更新上游凭据 |
| 424 | `SOURCE_REAUTH_REQUIRED` | 不重试；通知管理员重新导入 Outlook 凭据 |
| 424 | `SOURCE_EXPIRED_OR_DISABLED` | 不重试；通知管理员检查 FlySMS 权益 |
| 429 | `RATE_LIMITED` / `SOURCE_RATE_LIMITED` | 尊重 `Retry-After` 后重试 |
| 502 | `UPSTREAM_FAILURE` / `UPSTREAM_SCHEMA_CHANGED` | 仅在 `retryable=true` 时有限重试；格式变化需管理员处理 |
| 503 | `SOURCE_SYNCING` | 按 `Retry-After` 重试 |
| 504 | `UPSTREAM_TIMEOUT` | 指数退避后有限重试 |

推荐重试原则：

- 优先让单次请求使用 `wait_seconds=30`，不要每秒轮询；
- 最多重试 2～3 次；
- 尊重 HTTP `Retry-After` 或 JSON `retry_after_seconds`；
- 无提示时可使用 2 秒、5 秒的指数退避；
- 401、409、422、424 不应自动无限重试；
- 日志只记录错误码、HTTP 状态、`request_id` 和耗时，不记录 Token、验证码或完整响应体。

## 9. API Token 签发与轮换（管理员）

建议每个调用项目签发独立 Token。例如：

```bash
sudo -u coderelay /usr/local/bin/coderelay \
  generate-api-token \
  --hash-file /etc/coderelay/secrets/api-project-a.sha256
```

服务器端只保存 Token 的 SHA-256 hash。明文 Token 只显示一次，应直接保存进消费项目的 secret manager。

在 `/etc/coderelay/config.toml` 中列出允许的 Token hash 文件：

```toml
[security]
api_token_hash_files = [
  "/etc/coderelay/secrets/api-project-a.sha256",
  "/etc/coderelay/secrets/api-project-b.sha256",
]
```

安全轮换流程：

```text
1. 新增一个 Token hash 文件
2. 重启 CodeRelay
3. 将新 Token 配置到消费项目
4. 验证新 Token 可以调用
5. 从配置中删除旧 hash 文件
6. 再次重启 CodeRelay
```

不要覆盖旧 hash 后同时要求消费项目瞬间切换，否则会造成不必要的停机窗口。

## 10. 生产域名配置检查

CodeRelay 应保持只监听本机：

```toml
[server]
host = "127.0.0.1"
port = 8787
allowed_hosts = ["2fa.077.li", "localhost", "127.0.0.1"]
forwarded_allow_ips = "127.0.0.1"
access_log = false
```

其他建议：

```toml
[security]
cookie_secure = true
strict_secret_permissions = true
```

公网只能通过现有 Caddy 的 HTTPS 入口访问 `2fa.077.li`，不得直接开放 `8787` 端口。

## 11. 上线验收清单

从实际消费项目所在机器执行：

1. 无 Token 调用 `/api/v1/sources`，必须返回 `401`；
2. 错误 Token 调用，必须返回 `401`；
3. 正确 Token 调用 `/api/v1/sources`，必须返回 `200`；
4. TOTP 获取返回 `200` 且 `code` 为六位数字；
5. 触发一封新的 Outlook 验证码邮件；
6. 带正确 `not_before` 调用并得到 `200`；
7. 使用未来时间或未触发新邮件时不得返回旧验证码；
8. 验证响应包含 `Cache-Control: no-store`；
9. 检查消费项目和 CodeRelay 日志均无 Token、验证码和邮件正文；
10. 确认 VPS 防火墙没有对公网开放 `8787`。
