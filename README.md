# dsh-lan-access

**English** | [简体中文](README.zh-CN.md)

A [DeepSeek Harness](https://github.com/deepseek-ai/DeepSeek-Harness) web-profile bundle that makes the Web GUI work over **plain-http LAN IPs** (insecure browser contexts), and optionally lets the privileged settings / presets pages work from LAN hosts.

## Features

1. **`crypto.randomUUID` polyfill** (always on) — fixes the Web GUI hanging over a LAN IP.
2. **`allowPrivilegedFromLan`** (opt-in) — lets the 设置 → 通用设置 (Agent presets & permissions, settings, credentials) pages work from LAN devices, which DSH otherwise pins to loopback by design.

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

Requires `pnpm` (for `dsh plugin`) and the `web` profile:

```bash
# install the package into the web profile (adds it to dsh.profile.bundles automatically)
dsh plugin --profile web add dsh-lan-access

# restart the web app
dsh web
```

Offline / manual install (no pnpm): clone or download this repo, then

```bash
mkdir -p ~/.dsh/profiles/web/node_modules
ln -s "$PWD" ~/.dsh/profiles/web/node_modules/dsh-lan-access
# add "dsh-lan-access" to "dsh.profile.bundles" in ~/.dsh/profiles/web/package.json
```

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
| `lib/index.mjs` | the plugin — registers an index tap on `ctx.webServer` |

The plugin declares `inject: [webServer]` and uses `ctx.webServer.tapIndex()` to transform every served `index.html`, inserting the polyfill right after `<head>` — before any app bundle runs.

## Security note

Binding DSH to `0.0.0.0` exposes the GUI (which includes agent/workspace tooling) to your whole LAN. This bundle does **not** change any authorization behavior — it only makes the client code run on insecure origins. The trust fence (`--trusted-host`, LAN-literal auto-detection) still applies unchanged. Use on trusted networks only.

## License

MIT
