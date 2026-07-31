# CodeRelay

[![CI](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml/badge.svg)](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml)

CodeRelay 是一个面向单用户的验证码聚合服务，当前只支持三类来源：

1. 预配置 TOTP Secret，生成六位验证码；
2. `email----password----client_id----refresh_token` Outlook 凭据，通过 OAuth + IMAP 读取验证码邮件；
3. FlySMS iCloud 取件接口。

CodeRelay 不保存 Outlook 密码，不修改邮件，不把上游 token 或验证码写入正常日志，也不需要 Microsoft Graph 或 Microsoft App 注册。

## 安全提醒

本服务保存的凭据具有很高权限。请：

- 使用独立 Linux 用户运行；
- 所有 secret 文件设置为 `0600`，目录设置为 `0700`；
- 只监听 `127.0.0.1`，由服务器已有的 HTTPS 反向代理转发；
- 不把 `config.toml`、`secrets/`、`data/` 提交到版本库；
- 不在命令行参数、URL 或聊天中粘贴真实 secret；
- 四段式 Outlook 凭据中的密码只用于兼容输入格式，导入后立即丢弃；
- 已经公开过的 Outlook/FlySMS 凭据必须轮换。

## 1. 构建单文件程序

二进制必须在与目标 VPS **相同 CPU 架构、兼容或更旧 glibc** 的 Linux 环境构建。PyInstaller 不是跨平台编译器。

```bash
./scripts/build-binary.sh
./dist/coderelay --version
```

产物：

```text
dist/coderelay
dist/coderelay.sha256
```

校验构建产物：

```bash
(cd dist && sha256sum -c coderelay.sha256)
```

如果存在 `requirements.lock`，构建脚本会优先使用锁定依赖。

## 2. 创建运行目录

下面仅是示例路径：

```bash
install -d -m 700 /opt/coderelay/{secrets,data}
install -m 755 dist/coderelay /opt/coderelay/coderelay
install -m 600 config.example.toml /opt/coderelay/config.toml
cd /opt/coderelay
```

修改 `config.toml` 中的域名、来源 ID 和提取规则。相对路径都以 `config.toml` 所在目录为基准。

## 3. 生成本服务凭据

### API Bearer Token

```bash
./coderelay generate-api-token --hash-file secrets/api-token.sha256
```

程序只显示一次明文 API Token。把它保存在调用方的 secret 管理中；服务端只保存 SHA-256 hash。

### 网页密码

```bash
./coderelay hash-password --output secrets/ui-password.argon2
```

密码不会作为命令行参数出现。

### Session 签名密钥

```bash
./coderelay generate-key --output secrets/session.key
```

## 4. 配置三类来源

所有文件创建后执行：

```bash
chmod 600 secrets/*
chmod 700 secrets data
```

### 4.1 TOTP

`secret_file` 可以包含：

- 一个 Base32 secret；或
- 完整的 `otpauth://totp/...` URI。

文件中只放 secret 本身和末尾换行。MVP 只允许六位 TOTP。

### 4.2 Outlook 四段式凭据

配置示例：

```toml
[[sources]]
id = "outlook_primary"
type = "outlook_imap"
display_name = "Outlook"
credential_file = "data/outlook-credential.enc"
credential_key_file = "secrets/outlook-credential.key"
token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
imap_host = "outlook.office365.com"
imap_port = 993
imap_timeout_seconds = 15.0
poll_interval_seconds = 2.0
max_messages = 10
max_message_bytes = 262144
```

先生成加密密钥：

```bash
./coderelay generate-key --output secrets/outlook-credential.key
```

然后导入四段式凭据：

```bash
./coderelay outlook-import \
  --config config.toml \
  outlook_primary
```

CLI 会通过隐藏输入提示粘贴：

```text
email----password----client_id----refresh_token
```

也可以让受控的 secret manager 直接向标准输入写入一行：

```bash
secret-manager-command | ./coderelay outlook-import \
  --config config.toml \
  --credential-stdin \
  outlook_primary
```

不要为了导入而在磁盘上新建明文 `credential.txt`。

导入后：

- password 字段不会保存；
- email、client_id、refresh_token 保存在 AES-GCM 加密文件中；
- Microsoft 返回新的 refresh token 时，服务会自动原子更新加密文件；
- IMAP 使用 XOAUTH2；
- Inbox 以 readonly 模式打开；
- 邮件正文使用 `BODY.PEEK` 读取，不会标记已读。

如果需要替换凭据，先停止服务：

```bash
./coderelay outlook-import \
  --config config.toml \
  --replace \
  outlook_primary
```

### 4.3 FlySMS

分别将取件邮箱和 `tok_...` token 写入：

```text
secrets/flysms-email
secrets/flysms-token
```

不要保存完整的 `#email=...&key=...` URL。适配器直接使用请求头调用 JSON API，并将此来源标记为 `experimental`。FlySMS 冷同步可能需要数个上游请求；服务使用有限的 45 秒 Provider 预算和 20 秒单请求读取超时，超出后明确返回上游超时，不会无限挂起。

## 5. 校验并启动

```bash
./coderelay validate-config --config config.toml
./coderelay serve --config config.toml
```

默认监听：

```text
127.0.0.1:8787
```

生产环境必须由现有 HTTPS 反向代理访问。`forwarded_allow_ips` 默认只信任本机 `127.0.0.1` 的代理头。

健康检查：

```text
GET /health/live
GET /health/ready
```

## 6. API

提供给其他项目的完整鉴权、超时、错误处理和多语言调用说明见 [`docs/API调用指南.md`](docs/API调用指南.md)。生产域名为 `https://2fa.077.li`。

### 来源列表

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  https://2fa.077.li/api/v1/sources
```

### TOTP

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  'https://2fa.077.li/api/v1/codes/primary_totp?min_ttl=5'
```

### Outlook 或 FlySMS 邮件验证码

调用方应在触发上游发送验证码时记录 UTC 时间，并作为 `not_before`：

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  'https://2fa.077.li/api/v1/codes/outlook_primary?not_before=2026-07-30T03%3A00%3A00Z&wait_seconds=20'
```

重要参数：

- `not_before`：只接受该 UTC 时间后的邮件；
- `wait_seconds`：没有新邮件时允许继续轮询 0～30 秒；已开始的上游读取使用独立的有限超时，不会被过短的等待参数截断，因此实际 HTTP 时长可能略高于该值；
- `min_ttl`：TOTP 至少还需有效多少秒。

所有验证码响应包含 `Cache-Control: no-store, private`。

## 7. 网页

访问服务根路径即可登录。网页凭据与机器 API Token 分开：

- 网页使用 Argon2id 密码 + 短期 HttpOnly session cookie；
- API 使用高熵 Bearer Token；
- 浏览器不会将 API Token、验证码或上游 token 写入 localStorage；
- 邮箱验证码显示 90 秒后自动隐藏。

## 8. 配置提取规则

建议为每个邮件来源配置已知发件人或域名：

```toml
[sources.extractor]
senders = ["no-reply@example.com"]
sender_domains = ["example.com"]
subject_keywords = ["verification", "验证码"]
patterns = ['(?i)(?:code|验证码)\D{0,20}(?P<code>\d{6})']
max_age_seconds = 600
allow_generic_fallback = true
generic_requires_keyword = true
```

如果某个 Outlook 来源的验证码邮件只有裸六位数字，可以设置：

```toml
generic_requires_keyword = false
```

更安全的做法是同时配置发件人和精确正则，并在 API 请求中传 `not_before`。如果多个验证码候选得分相同，API 返回 `AMBIGUOUS_CODE`，不会随机选择。

每个自定义正则必须包含命名组 `(?P<code>...)`。

## 9. CLI

```text
coderelay serve
coderelay validate-config
coderelay generate-api-token
coderelay hash-password
coderelay generate-key
coderelay outlook-import
coderelay --version
```

使用 `CODERELAY_CONFIG=/path/config.toml` 可设置默认配置路径。

## 10. 开发测试

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
pytest
```

测试覆盖：

- TOTP RFC 向量；
- 加密 Outlook 凭据导入和 refresh token 轮换；
- IMAP XOAUTH2、readonly、`BODY.PEEK` 和 MIME 正文解析；
- FlySMS JSON 契约；
- 验证码提取和新鲜度；
- API/UI 鉴权和安全响应头；
- PyInstaller 二进制 smoke test。

真实 Outlook/FlySMS token 不应出现在测试、fixture 或 CI 中。
