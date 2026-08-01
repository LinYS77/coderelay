# CodeRelay

[![CI](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml/badge.svg)](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml)

CodeRelay 是一个单用户、API-only、无状态的验证码解析服务。调用项目在每次请求中提交本次上游凭据，CodeRelay 临时完成取码并返回 JSON，不在服务器持久化 TOTP、Outlook 或 FlySMS 凭据。

支持：

1. Base32 TOTP Secret 或 `otpauth://totp/...`；
2. `email----password----client_id----refresh_token` Outlook 凭据；
3. `email---token---https://flysms.xyz/icloud/pickup#...` FlySMS 凭据。

生产域名：

```text
https://2fa.077.li
```

完整调用契约见 [`docs/API调用指南.md`](docs/API调用指南.md)。

面向 1 vCPU / 2 GiB、稳定 20 并发的 Go 重写设计见 [`docs/Go重写方案书-v1.0.md`](docs/Go重写方案书-v1.0.md)。该文档目前是实施方案，当前生产实现仍为 Python 0.3.0。

## 核心边界

```text
有 CodeRelay Bearer Token 的调用项目
        │ POST /api/v1/code（请求体携带本次上游凭据）
        ▼
CodeRelay
        ├─ TOTP：本地计算
        ├─ Outlook：OAuth refresh + readonly IMAP + BODY.PEEK
        └─ FlySMS：固定 JSON API
        │
        ▼
{"code":"123456"}
```

CodeRelay：

- 不把调用方上游凭据写入配置、文件或数据库；
- 不跨请求缓存上游凭据、access token、refresh token、邮件或验证码；
- 不记录请求正文、验证码或上游 token；
- 请求结束时主动释放应用层凭据引用；
- Outlook 密码字段只为兼容输入格式，解析后立即丢弃；
- Microsoft 返回轮换 refresh token 时，只通过 `credential_update` 返回给调用方，不在服务器保存；
- 只允许固定的 Microsoft、Outlook IMAP 和 FlySMS 上游地址，调用方不能指定任意 URL。

“无状态”不表示凭据从未进入内存：HTTPS 解密、JSON 解析和上游调用期间，凭据不可避免地短暂存在于进程内存。Python 也不能承诺物理内存清零；本项目保证的是不持久化、不记录、不跨请求保留。

## API

所有取码请求必须使用：

```http
Authorization: Bearer <CODERELAY_API_TOKEN>
Content-Type: application/json
```

唯一取码端点：

```http
POST /api/v1/code
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
  "credential": "email----password----client_id----refresh_token",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

### FlySMS

```json
{
  "type": "flysms",
  "credential": "email---token---https://flysms.xyz/icloud/pickup#email=...&key=...",
  "not_before": "2026-07-31T03:00:00Z",
  "wait_seconds": 30
}
```

成功：

```json
{"code":"123456"}
```

如果 Outlook 刷新时发生 token 轮换：

```json
{
  "code": "123456",
  "credential_update": {
    "refresh_token": "new_refresh_token"
  }
}
```

调用方必须把新 refresh token 更新到自己的 secret manager。即使没有找到新验证码，错误 JSON 也可能携带 `credential_update`。

`not_before` 建议在触发上游发送邮件之前记录，用于阻止旧验证码误匹配。

旧版以下接口已删除：

```text
GET /api/v1/sources
GET /api/v1/codes/{source_id}
```

## 服务鉴权

CodeRelay 自身只保存调用项目 API Token 的 SHA-256 hash。建议每个消费项目一把独立 Token：

```bash
./coderelay generate-api-token \
  --hash-file secrets/api-project-a.sha256
```

明文 Token 只显示一次，应放进消费项目的 secret manager。Token 只能通过 `Authorization` 请求头发送，不能放入 URL。

以下健康端点公开，但不返回任何来源、邮箱或验证码信息：

```text
GET /health/live
GET /health/ready
```

## 配置

复制示例：

```bash
install -m 600 config.example.toml config.toml
mkdir -p secrets
chmod 700 secrets
```

最小配置：

```toml
[server]
host = "127.0.0.1"
port = 8787
allowed_hosts = ["2fa.077.li", "localhost", "127.0.0.1"]
forwarded_allow_ips = "127.0.0.1"
access_log = false

[security]
api_token_hash_files = ["secrets/api-project-a.sha256"]
strict_secret_permissions = true
api_rate_limit_per_minute = 60
```

配置中没有 TOTP、Outlook 或 FlySMS 凭据。

校验：

```bash
./coderelay validate-config --config config.toml
```

## 构建单文件程序

```bash
./scripts/build-binary.sh
./dist/coderelay --version
(cd dist && sha256sum -c coderelay.sha256)
```

PyInstaller 不是跨平台编译器。应在与目标 VPS 相同 CPU 架构、且 glibc 不高于目标 VPS 的 Linux 环境构建。

## 启动

```bash
./coderelay serve --config config.toml
```

默认只监听：

```text
127.0.0.1:8787
```

公网只能通过现有 Caddy 的 HTTPS 入口访问，不能直接开放 8787。

## CLI

```text
coderelay serve
coderelay validate-config
coderelay generate-api-token
coderelay --version
```

旧版持久化相关命令已经删除：

```text
outlook-import
hash-password
generate-key
```

## 安全调用示例

```bash
secret-manager-render-coderelay-json | curl --fail-with-body \
  --connect-timeout 5 \
  --max-time 75 \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data-binary @- \
  https://2fa.077.li/api/v1/code
```

不要在命令行参数中内联真实 credential，也不要为了调用创建明文 `request.json`；应从消费项目内存或 secret manager 直接构造请求体。

## 错误处理

错误响应：

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

重要状态：

- `401 AUTHENTICATION_REQUIRED`：CodeRelay Bearer Token 缺失或无效；
- `404 NO_FRESH_CODE`：没有符合新鲜度的验证码；
- `409 AMBIGUOUS_CODE`：多个候选无法安全判定；
- `422 INVALID_CODE_REQUEST`：请求级 credential 格式无效；
- `424 SOURCE_REAUTH_REQUIRED`：Outlook refresh token 需要调用方更新；
- `429 RATE_LIMITED` / `SOURCE_RATE_LIMITED`：尊重 `Retry-After`；
- `502/503/504`：上游失败、同步中或超时。

所有 API 响应设置 `Cache-Control: no-store`。调用项目也不得缓存或记录成功响应。

## 开发测试

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
ruff check coderelay tests binary_entry.py
```

测试覆盖：

- 无 Bearer Token 无法取码；
- 请求体 credential 不出现在验证错误中；
- TOTP RFC 向量；
- Outlook password 丢弃、refresh token 轮换、XOAUTH2、readonly 和 `BODY.PEEK`；
- FlySMS 三段式一致性校验和 SSRF 防护；
- `not_before`、旧码拒绝和歧义检测；
- Provider 请求结束清理；
- 有限轮询、超时和限流；
- PyInstaller 单文件 smoke test。

真实凭据不得进入 fixture、Git 或 CI。
