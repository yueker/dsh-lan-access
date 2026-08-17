# dsh-lan-access

[English](README.md) | **简体中文**

一个 [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) Web 配置（profile）bundle，让 Web GUI 能通过 **纯 HTTP 局域网 IP**（非安全上下文）正常使用，并可选择性地让设置/预设等特权页面在局域网设备上可用。

## 功能

1. **`crypto.randomUUID` polyfill**（默认启用）—— 修复局域网 IP 访问时 Web GUI 卡死的问题。
2. **`allowPrivilegedFromLan`**（可选开启）—— 让 设置 → 通用设置（Agent 预设与权限、设置、凭据）页面在局域网设备上可用（DSH 默认把这些方法限制在回环地址）。
3. **`authPassword`**（可选开启）—— 为整个 `/api` 平面（HTTP + WebSocket）加密码门禁，并注入登录界面；DSH 本身没有 Web 认证。

## 问题

DSH Web GUI 在客户端连接握手中使用 `crypto.randomUUID()`（Chrome 中**仅安全上下文可用**）生成 RPC id。当通过纯 HTTP 的局域网 IP（如 `http://192.168.2.102:3080`）访问 GUI 时，该源**不是**安全上下文，于是：

1. `crypto.randomUUID()` 未定义并抛出 `TypeError`
2. 连接握手（`host.describe`）在**发出任何请求之前**就失败
3. WebSocket 被关闭（关闭码 1006），界面无限循环：
   `[web-runtime] connection lost, retry #N`
4. 页面一直卡在欢迎页——看不到会话，也看不到工作区

`http://localhost` 正常，因为 localhost 属于安全上下文——这就是为什么在服务器本机正常、但从其他局域网设备访问却坏掉的原因。

## 修复

本 bundle 通过 `webServer` 的 index-tap 向每个被服务的 `index.html` 注入一段小 `<script>`，用 `crypto.getRandomValues()` 定义 `crypto.randomUUID()`——该 API 在**非安全上下文也可用**。polyfill 是符合规范的 RFC 4122 v4 UUID 生成器，仅在原生方法缺失时安装。

## 安装

需要 `pnpm`（供 `dsh plugin` 使用）和 `web` profile：

```bash
# 将包安装到 web profile（会自动加入 dsh.profile.bundles）
dsh plugin --profile web add dsh-lan-access

# 重启 web 应用
dsh web
```

离线/手动安装（无 pnpm）：克隆或下载本仓库，然后

```bash
mkdir -p ~/.dsh/profiles/web/node_modules
ln -s "$PWD" ~/.dsh/profiles/web/node_modules/dsh-lan-access
# 在 ~/.dsh/profiles/web/package.json 的 "dsh.profile.bundles" 中加入 "dsh-lan-access"
```

## 局域网使用特权方法（可选开启）

DSH 出于设计把一组特权方法——`settings.*`、`credentials.*`、`agentPreset.*`、`host.pickDirectory`、`host.openPath`、`llm.discoverModels`——限制在回环地址（局域网信任围栏明确**不是**认证）。因此设置/Agent 预设/权限页面从局域网设备访问会返回 `403`。

要在局域网启用，请在 profile patch 中给插件行加配置：

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: secure-context-polyfill
  config:
    allowPrivilegedFromLan: true
```

> ⚠️ **安全提示**：这会有意削弱 DSH 对特权方法的回环限制，仅剩普通的局域网信任围栏（`--trusted-host`、自动检测的局域网 IP）。请仅在受信任的网络上使用。

## 密码鉴权（可选开启）

DSH **没有**内置 Web 认证（官方注释："until a real authentication layer exists"——在真正认证层出现之前）。当 GUI 可以被其他设备访问时，网络上任何人都能使用。要加密码门禁，设置 `authEnabled`：

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: secure-context-polyfill
  config:
    authEnabled: true
```

**首次使用**：第一个访问者会看到"设置访问密码"界面。密码以加盐（scrypt）形式存储在 `$DSH_HOME/lan-access-password.json`（权限 0600），重启后依然有效。

**之后每次访问**：显示登录界面。登录后页面右下角会出现"修改密码"按钮，可在网页上直接修改密码（修改后其他已登录设备需重新登录）。

也可以选择在配置中固定密码：`authPassword: '...'`（此时网页修改密码不可用，需改配置）。

鉴权覆盖范围：

- 所有 `/api` 请求（HTTP 和 WebSocket，包括事件流）都需要会话 cookie；未认证请求返回 `401` / WebSocket 升级被拒绝
- 会话使用 `HttpOnly` + `SameSite=Strict` cookie，token 存储在内存（12 小时有效期，重启后失效）
- 接口：`POST /api/__lan_auth.status`、`POST /api/__lan_auth.setup`（仅首次）、`POST /api/__lan_auth.login`、`POST /api/__lan_auth.logout`、`POST /api/__lan_auth.changePassword`（需已登录）

> ⚠️ **安全提示**：这是面向受信任局域网的便利性门禁，**不是**加固的安全边界。密码和会话 cookie 通过纯 HTTP 明文传输（无 TLS）、密码为所有被授权者共享、对暴力破解只有很轻的限制。需要更强保护时，请在 DSH 前面加 TLS 反向代理并配合真正的认证方案。

## 验证

重启后：

```bash
curl -s http://127.0.0.1:3080/ | grep -c randomUUID   # ≥ 2 表示 polyfill 已注入
```

然后从其他设备打开 `http://<你的局域网IP>:3080` 并强制刷新（`Ctrl+Shift+R`）。

## 工作原理

| 组件 | 作用 |
|---|---|
| `cordis.patch.yml` | bundle patch —— 插入一个 host 行（`secure-context-polyfill`） |
| `lib/index.mjs` | 插件本体 —— 在 `ctx.webServer` 上注册 index-tap |

插件声明 `inject: [webServer]`，用 `ctx.webServer.tapIndex()` 转换每个被服务的 `index.html`，在 `<head>` 之后（任何应用 bundle 运行之前）插入 polyfill。

## 安全提示

将 DSH 绑定到 `0.0.0.0` 会把 GUI（包含 agent/工作区工具）暴露给整个局域网。本 bundle **不改变任何授权行为**——它只是让客户端代码在非安全源上可以运行。信任围栏（`--trusted-host`、局域网字面量自动检测）依然原样生效。请仅在受信任的网络上使用。

## 许可证

MIT
