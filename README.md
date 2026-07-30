# CodeRelay

[![CI](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml/badge.svg)](https://github.com/LinYS77/coderelay/actions/workflows/ci.yml)

CodeRelay 是一个面向单用户的验证码聚合服务：

- 从预配置的 TOTP Secret 生成六位验证码；
- 通过 Microsoft Graph 读取 Outlook 验证码邮件；
- 通过 FlySMS 当前取件 JSON 接口读取验证码邮件；
- 提供 Bearer Token API 和一个简洁的受保护网页；
- 可用 PyInstaller 构建成单文件 Linux 可执行程序。

CodeRelay 不保存 Outlook 密码，不修改邮件，也不会把上游 token 或验证码写入正常日志。

## 安全提醒

本服务保存的凭据具有很高权限。请：

- 使用独立 Linux 用户运行；
- 所有 secret 文件设置为 `0600`，目录设置为 `0700`；
- 只监听 `127.0.0.1`，由服务器已有的 HTTPS 反向代理转发；
- 不把 `config.toml`、`secrets/`、`data/` 提交到版本库；
- 不在命令行参数、URL 或聊天中粘贴真实 secret；
- 部署前轮换曾经公开过的 Outlook/FlySMS 凭据。

## 1. 构建单文件程序

二进制必须在与目标 VPS **相同 CPU 架构、兼容或更旧 glibc** 的 Linux 环境构建。PyInstaller 不是跨平台编译器。

```bash
./scripts/build-binary.sh
./dist/coderelay --version
```

首次构建会创建 `.venv-build/` 并安装构建依赖，产物位于：

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

### MSAL cache 加密密钥

```bash
./coderelay generate-key --output secrets/msal-cache.key
```

## 4. 配置来源 secret

所有文件创建后执行：

```bash
chmod 600 secrets/*
chmod 700 secrets data
```

### TOTP

`secret_file` 可以包含：

- 一个 Base32 secret；或
- 完整的 `otpauth://totp/...` URI。

文件中只放 secret 本身和末尾换行。建议使用权限受控的编辑器或从密码管理器写入，避免把 secret 放入 shell history。

MVP 只允许六位 TOTP。

### FlySMS

分别将取件邮箱和 `tok_...` token 写入：

```text
secrets/flysms-email
secrets/flysms-token
```

不要保存完整的 `#email=...&key=...` URL。适配器直接使用请求头调用 JSON API，并将此来源标记为 `experimental`。

### Microsoft Graph

1. 在 Microsoft Entra 中注册自己控制的应用；
2. Supported account types 选择“Personal Microsoft accounts only”，或包含个人账户的类型；
3. 开启 public client/device code flow；
4. 添加 delegated `Mail.Read`；不要添加 `Mail.ReadWrite`；
5. 将 Application (client) ID 写入 `secrets/ms-client-id`；
6. 确认 `config.toml` 中 authority 为：

```text
https://login.microsoftonline.com/consumers
```

然后在 CodeRelay 服务停止时执行：

```bash
./coderelay outlook-login --config config.toml outlook_primary
```

根据终端提示在浏览器中登录并授权。程序不会打印 access token 或 refresh token，结果保存到加密的 MSAL cache。

如果 cache 可能包含多个账户，请在对应来源设置：

```toml
account_username = "your-account@outlook.com"
```

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

### 来源列表

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  https://codes.example.com/api/v1/sources
```

### TOTP

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  'https://codes.example.com/api/v1/codes/primary_totp?min_ttl=5'
```

### 等待一封新的邮件验证码

调用方应在触发上游发送验证码时记录 UTC 时间，并作为 `not_before`：

```bash
curl --fail-with-body \
  -H "Authorization: Bearer ${CODERELAY_API_TOKEN}" \
  'https://codes.example.com/api/v1/codes/outlook_primary?not_before=2026-07-30T03%3A00%3A00Z&wait_seconds=20'
```

重要参数：

- `not_before`：只接受该 UTC 时间后的邮件；
- `wait_seconds`：没有新邮件时等待 0～30 秒；
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

默认情况下，即使启用通用六位数 fallback，候选附近也必须出现“验证码 / verification code / security code / code / OTP”等关键词；这可以避免把订单号当成验证码。若某个固定来源的邮件真的只有裸六位数字，应优先为它配置精确的自定义 `patterns`，而不是全局放宽规则。

每个自定义正则必须包含命名组 `(?P<code>...)`。如果多个验证码候选得分相同，API 返回 `AMBIGUOUS_CODE`，不会随机选择。

## 9. CLI

```text
coderelay serve
coderelay validate-config
coderelay generate-api-token
coderelay hash-password
coderelay generate-key
coderelay outlook-login
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

真实 Outlook/FlySMS token 不应出现在测试、fixture 或 CI 中。Provider 测试使用模拟 HTTP 响应。
