# dsh-lan-access

**English** | [简体中文](README.zh-CN.md)

A [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) web-profile bundle that makes the Web GUI work over **plain-http LAN IPs** (insecure browser contexts), and optionally lets the privileged settings / presets pages work from LAN hosts.

## Features

1. **`crypto.randomUUID` polyfill** (always on) — fixes the Web GUI hanging over a LAN IP.
2. **`allowPrivilegedFromLan`** (opt-in) — lets the 设置 → 通用设置 (Agent presets & permissions, settings, credentials) pages work from LAN devices, which DSH otherwise pins to loopback by design.
3. **`authEnabled`** (opt-in) — password gate for the whole `/api` plane (HTTP + WebSocket) with first-use password setup and in-web password change; DSH ships no web authentication.

## Problem

The DSH Web GUI uses `crypto.randomUUID()` (Chrome: **secure-context-only**) to mint RPC ids in its client connection handshake. When you open the GUI over a LAN IP over plain HTTP (e.g. `http://192.168.2.102:3080`), the origin is **not** a secure context, so:

1. `crypto.randomUUID()` is undefined and throws `TypeError`
2. the connection handshake (`host.describe`) rejects **before any request is sent**
3. the WebSockets are torn down (close code 1006) and the UI loops forever:
   `[web-runtime] connection lost, retry #N`
4. the page stays stuck on the welcome screen — no sessions, no workspace visible

`http://localhost` works because localhost counts as a secure context — which is why the GUI is fine on the server itself but broken from other LAN devices.

## Fix

This bundle injects a tiny `<script>` into every served `index.html` (via the `webServer` index-tap) that defines `crypto.randomUUID()` using `crypto.getRandomValues()` — an API that **is** available on insecure origins. The polyfill is a spec-compliant RFC 4122 v4 UUID generator, installed only when the native method is missing.

## Install

### Prerequisites

- DSH with the `web` profile already booted at least once (the profile lives in `~/.dsh/profiles/web/`, or `$DSH_HOME/profiles/web/` if `DSH_HOME` is set).
- `git` and network access to GitHub (to fetch the plugin).
- A terminal on the machine running DSH.

All commands below are for Linux / macOS. On Windows (PowerShell), replace `ln -s <target> <link>` with `New-Item -ItemType SymbolicLink -Path <link> -Target <target>` (run as administrator or enable Developer Mode), and the paths use `%USERPROFILE%\.dsh\...`.

### Step 1 — Get the plugin

Clone the repository (or download the repo as a ZIP from GitHub and extract it):

```bash
git clone https://github.com/yueker/dsh-lan-access.git ~/dsh-lan-access
```

> No `git`? Download `dsh-lan-access` from the GitHub page (**Code → Download ZIP**), extract it, and use the extracted folder path in Step 2 (note: a ZIP extracts to `dsh-lan-access-main`).

### Step 2 — Put the plugin where the web profile can load it

```bash
mkdir -p ~/.dsh/profiles/web/node_modules
ln -s ~/dsh-lan-access ~/.dsh/profiles/web/node_modules/dsh-lan-access
```

Verify the link exists:

```bash
ls -l ~/.dsh/profiles/web/node_modules/
# dsh-lan-access -> /home/<you>/dsh-lan-access
```

> If you extracted a ZIP instead, the target folder is `dsh-lan-access-main`:
> `ln -s ~/dsh-lan-access-main ~/.dsh/profiles/web/node_modules/dsh-lan-access`

### Step 3 — Register the plugin as a profile bundle

Edit `~/.dsh/profiles/web/package.json`:

1. add `"dsh-lan-access": "file:./node_modules/dsh-lan-access"` to the `dependencies` object;
2. append `"dsh-lan-access"` to the `dsh.profile.bundles` array (after `@deepseek-ai/dsh-web-app`).

Complete example (keep any entries your profile already has):

```json
{
  "name": "dsh-profile-web",
  "private": true,
  "dependencies": {
    "dsh-lan-access": "file:./node_modules/dsh-lan-access"
  },
  "dsh": {
    "profile": {
      "bundles": [
        "@deepseek-ai/dsh-base",
        "@deepseek-ai/dsh-web-app",
        "dsh-lan-access"
      ]
    }
  }
}
```

### Step 4 — Configure the profile patch

Edit `~/.dsh/profiles/web/cordis.patch.yml`:

```yaml
# 1) Bind the Web server to all interfaces so LAN devices can reach it.
- id: webserver
  config:
    host: '0.0.0.0'
    port: 3080

# 2) Enable the plugin's LAN fixes.
- id: secure-context-polyfill
  config:
    allowPrivilegedFromLan: true   # optional: settings/presets pages from LAN
    authEnabled: true              # optional: password gate (set on first use)
```

- `host: '0.0.0.0'` is required for LAN access. Pick any free `port`.
- `allowPrivilegedFromLan` and `authEnabled` are optional — read the [Privileged methods from LAN](#privileged-methods-from-lan-opt-in) and [Password authentication](#password-authentication-opt-in) sections before enabling them.

### Step 5 — Restart the web app

In the terminal that is running `dsh web`, press `Ctrl+C`, then start it again:

```bash
dsh web
```

### Step 6 — Verify

On the server:

```bash
curl -s http://127.0.0.1:3080/ | grep -c randomUUID   # ≥ 2 = polyfill injected
```

From another device on the same network, open `http://<server-lan-ip>:3080` and hard-refresh (`Ctrl+Shift+R`). With `authEnabled: true`, the first visitor sees the **create-password** screen.

### Alternative install: `dsh plugin` (requires pnpm)

If pnpm is installed, `dsh plugin` installs and registers the bundle in one step:

```bash
# once the package is published to an npm registry:
dsh plugin --profile web add dsh-lan-access

# or directly from a local checkout of this repository:
dsh plugin --profile web add /path/to/dsh-lan-access

dsh web
```

### Updating

```bash
cd ~/dsh-lan-access && git pull
# then restart dsh web (Ctrl+C, then dsh web)
```

(This works for the symlink install. If you copied the folder instead of symlinking, re-copy the updated folder over it.)

## Privileged methods from LAN (opt-in)

DSH gates a set of privileged methods — `settings.*`, `credentials.*`, `agentPreset.*`, `host.pickDirectory`, `host.openPath`, `llm.discoverModels` — to loopback by design (the LAN trust fence is explicitly **not** authentication). The settings / agent-preset / permissions pages therefore return `403` from LAN devices.

To enable them from LAN, add the config to the plugin row in your profile patch:

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: secure-context-polyfill
  config:
    allowPrivilegedFromLan: true
```

> ⚠️ **Security**: this intentionally weakens DSH's loopback pin for privileged methods. Only the ordinary LAN trust fence (`--trusted-host`, auto-detected LAN IPs) remains. Use on trusted networks only.

## Password authentication (opt-in)

DSH ships **no** web authentication ("until a real authentication layer exists"). When the GUI is reachable from other devices, anyone on the network can use it. To add a password gate, set `authEnabled`:

```yaml
# ~/.dsh/profiles/web/cordis.patch.yml
- id: secure-context-polyfill
  config:
    authEnabled: true
```

**First use**: the first visitor sees a "create password" screen. The password is stored salted (scrypt) at `$DSH_HOME/lan-access-password.json` (mode 0600) and survives restarts.

**Every later visit**: a login screen. After signing in, a "修改密码 / change password" button appears at the bottom-right corner of the page to change the password from the web UI (all other sessions are invalidated on change).

Alternatively, pin a fixed password in the profile config with `authPassword: '...'` (then the change-password UI is disabled; edit the config instead).

What the gate covers:

- every `/api` request (HTTP and WebSocket, including the event streams) requires a session cookie; unauthenticated requests get `401` / the WebSocket upgrade is rejected
- sessions are `HttpOnly` + `SameSite=Strict` cookies backed by a token store persisted under `$DSH_HOME/lan-access-sessions.json` (12 h TTL, only SHA-256 token hashes stored, survives restarts)
- endpoints: `POST /api/__lan_auth.status`, `POST /api/__lan_auth.setup` (first-use only), `POST /api/__lan_auth.login`, `POST /api/__lan_auth.logout`, `POST /api/__lan_auth.changePassword` (signed-in)

> ⚠️ **Security**: this is a convenience gate for trusted LANs, **not** a hardened boundary. Credentials and the session cookie travel over plain HTTP (no TLS), the password is shared by everyone granted access, and brute-force is only lightly throttled. For stronger protection run DSH behind a TLS reverse proxy with real authentication.

## Verify

After restarting:

```bash
curl -s http://127.0.0.1:3080/ | grep -c randomUUID   # ≥ 2 means the polyfill is injected
```

Then open `http://<your-lan-ip>:3080` from another device and hard-refresh (`Ctrl+Shift+R`).

## How it works

| Component | Role |
|---|---|
| `cordis.patch.yml` | bundle patch — inserts one host row (`secure-context-polyfill`) |
| `lib/index.mjs` | the plugin — index tap (polyfill + auth client) and `/api` handler wraps (privileged LAN bypass, auth gate) |

The plugin declares `inject: [webServer]` and uses `ctx.webServer.tapIndex()` to transform every served `index.html`, inserting the polyfill right after `<head>` — before any app bundle runs. The optional `allowPrivilegedFromLan` and `authEnabled` features wrap the registered `/api` route handler and the WebSocket upgrade routes, so the auth gate and the loopback re-targeting sit in front of DSH's own pipeline.

## Security note

Binding DSH to `0.0.0.0` exposes the GUI (which includes agent/workspace tooling) to your whole LAN. This bundle does **not** change any authorization behavior — it only makes the client code run on insecure origins. The trust fence (`--trusted-host`, LAN-literal auto-detection) still applies unchanged. Use on trusted networks only.

## License

MIT
