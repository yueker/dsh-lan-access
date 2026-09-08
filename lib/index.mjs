const LAN_OWNS_HOST = `<script>(function () {
  try {
    globalThis.__DSH_TRANSPORT__ = Object.assign({}, globalThis.__DSH_TRANSPORT__, {
      ownsHost: true
    });
  } catch (e) {}
})();<\/script>`;

/**
 * dsh-lan-access — host plugin entry.
 *
 * Three optional fixes for running the DSH Web GUI over a plain-http LAN IP
 * (an insecure browser context):
 *
 * 1. crypto.randomUUID polyfill (always active). Chrome exposes
 *    Crypto.randomUUID only in secure contexts; on http://<lan-ip> it is
 *    undefined, the client connection handshake (AbstractApiClient.mintRpcId)
 *    rejects before any request is sent, and the GUI loops "connection lost,
 *    retry #N" forever with no sessions or workspace. crypto.getRandomValues
 *    IS available on insecure origins, so a UUID v4 built from it restores
 *    full functionality. Injected via the webServer index tap.
 *
 * 2. allowPrivilegedFromLan (opt-in, default false). DSH gates privileged API
 *    methods to loopback by design. When explicitly enabled, every authenticated
 *    /api request from a trusted LAN host is re-dispatched to loopback authority.
 *    This avoids maintaining a version-sensitive method allowlist. Enable only
 *    on trusted networks and preferably together with authEnabled.
 *
 * 3. authEnabled / authPassword (opt-in). A password gate for the whole /api
 *    plane (HTTP + WebSocket), because DSH itself ships no web authentication
 *    ("until a real authentication layer exists"). Password sources:
 *      - config.authPassword — set it to pin a fixed password in the profile,
 *        or
 *      - first-use setup — with authEnabled: true (and no authPassword), the
 *        first visitor is asked to create a password, which is stored salted
 *        (scrypt) at $DSH_HOME/lan-access-password.json and survives restarts.
 *    Loopback TCP peers bypass the password gate; LAN peers authenticate.
 *    Sessions are HttpOnly + SameSite=Strict cookies backed by a token store
 *    persisted under $DSH_HOME/lan-access-sessions.json (12 h TTL, only
 *    SHA-256 token hashes stored, survives restarts).
 *    This is a convenience gate for trusted LANs, NOT a hardened security
 *    boundary: credentials travel over plain HTTP, and the password is shared
 *    by everyone who is granted access.
 */
import { createHash, createHmac, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { pathToFileURL } from "node:url";
import { homedir } from "node:os";

const scrypt = promisify(scryptCb);

export const name = "secure-context-polyfill";

export const inject = ["webServer"]; // connection patched via ctx.inject later

/** Session lifetime for the optional auth gate. */
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_COOKIE = "dsh_lan_auth";

/** Password store under the DSH home. */

function dshHome() {
  return process.env.DSH_HOME ?? join(homedir(), ".dsh");
}

function loadDshBrowserSecret() {
  const file = join(dshHome(), ".credentials.yaml");
  if (!existsSync(file)) return void 0;
  const text = readFileSync(file, "utf8");
  const match = text.match(/client-connection\/browser-session:[\s\S]*?secret:\s*([A-Za-z0-9_-]+)/);
  if (!match) return void 0;
  const value = match[1];
  const padding = "=".repeat((4 - value.length % 4) % 4);
  const decoded = Buffer.from(value.replaceAll("-", "+").replaceAll("_", "/") + padding, "base64");
  return decoded.byteLength === 32 ? decoded : void 0;
}

function encodeBase64Url(value) {
  return Buffer.from(value).toString("base64").replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function dshCookieName(authority) {
  return "dsh-auth-" + encodeBase64Url(createHash("sha256").update(authority).digest());
}

function issueDshBrowserCookie(req, maxAgeDays = 30, fallbackHost) {
  const secret = loadDshBrowserSecret();
  const host = (typeof req.headers.host === "string" && req.headers.host) || fallbackHost;
  if (!secret || typeof host !== "string" || host.length === 0) return void 0;
  let authority;
  try { authority = new URL(`http://${host}`).host; } catch { return void 0; }
  const issuedAt = Date.now();
  const expiresAt = issuedAt + maxAgeDays * 1440 * 60 * 1000;
  const body = encodeBase64Url(Buffer.from(JSON.stringify({ version: 1, authority, issuedAt, expiresAt }), "utf8"));
  const sig = encodeBase64Url(createHmac("sha256", secret).update(body).digest());
  const value = `v1.${body}.${sig}`;
  const maxAgeSeconds = Math.floor((expiresAt - issuedAt) / 1000);
  return `${dshCookieName(authority)}=${value}; Max-Age=${maxAgeSeconds}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict`;
}


function dshPiAiModule() {
  const argv1 = process.argv[1];
  const candidates = [];
  if (typeof argv1 === "string" && argv1.length > 0) {
    candidates.push(join(dirname(argv1), "../node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js"));
    candidates.push(join(dirname(argv1), "../../dsh-llm-pi-ai/lib/index.js"));
  }
  candidates.push("/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js");
  candidates.push("/usr/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-llm-pi-ai/lib/index.js");
  return candidates.find((file) => existsSync(file));
}

function dshClientConnectionModule() {
  const argv1 = process.argv[1];
  const candidates = [];
  if (typeof argv1 === "string" && argv1.length > 0) {
    candidates.push(join(dirname(argv1), "../node_modules/@deepseek-ai/dsh-client-connection/lib/index.js"));
    candidates.push(join(dirname(argv1), "../../dsh-client-connection/lib/index.js"));
  }
  candidates.push("/usr/local/lib/node_modules/@deepseek-ai/dsh/node_modules/@deepseek-ai/dsh-client-connection/lib/index.js");
  return candidates.find((file) => existsSync(file));
}

function attachDshBrowserCookie(req, fallbackHost) {
  const cookie = issueDshBrowserCookie(req, 30, fallbackHost);
  if (!cookie) return;
  const pair = cookie.split(";", 1)[0];
  const name = pair.split("=", 1)[0];
  const current = req.headers.cookie ?? "";
  if (!current.includes(`${name}=`)) req.headers.cookie = [current, pair].filter(Boolean).join("; ");
}


async function patchDshBrowserAuth() {
  const file = dshClientConnectionModule();
  const targets = [];
  if (file !== void 0) {
    try { targets.push(await import(pathToFileURL(file).href)); } catch (error) {
      console.warn("[dsh-lan-access] import connection module failed:", error);
    }
  }
  // Also patch whatever constructor is already on the running webServer/connection graph
  // by scanning loaded module namespace objects on import.meta is not available here.
  for (const mod of targets) {
    const proto = mod.HostConnectionService?.prototype;
    if (!proto || proto.authorizeIndex?.__lanAuthPatched) continue;
    const originalAuthorize = proto.authorizeIndex;
    proto.authorizeIndex = function (req, res) {
      attachDshBrowserCookie(req, req.headers.host);
      return originalAuthorize.call(this, req, res);
    };
    proto.authorizeIndex.__lanAuthPatched = true;
    if (typeof proto.requestRejection === "function") {
      const originalRejection = proto.requestRejection;
      proto.requestRejection = function (req) {
        attachDshBrowserCookie(req, req.headers.host);
        return originalRejection.call(this, req);
      };
    }
  }
}

function passwordFile() {
  const home = process.env.DSH_HOME ?? join(homedir(), ".dsh");
  return join(home, "lan-access-password.json");
}

/** Session store under the DSH home (token hashes -> expiry). */
function sessionsFile() {
  const home = process.env.DSH_HOME ?? join(homedir(), ".dsh");
  return join(home, "lan-access-sessions.json");
}

const POLYFILL = `<script>(function () {
  try {
    if (typeof crypto === "undefined") return;
    if (typeof crypto.randomUUID === "function") return;
    var uuidv4 = function () {
      var b = crypto.getRandomValues(new Uint8Array(16));
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      var h = Array.prototype.map.call(b, function (x) {
        return x.toString(16).padStart(2, "0");
      }).join("");
      return h.slice(0, 8) + "-" + h.slice(8, 12) + "-" + h.slice(12, 16) + "-" + h.slice(16, 20) + "-" + h.slice(20);
    };
    if (typeof Crypto !== "undefined" && Crypto.prototype) {
      Object.defineProperty(Crypto.prototype, "randomUUID", {
        configurable: true,
        writable: true,
        value: uuidv4
      });
    } else {
      crypto.randomUUID = uuidv4;
    }
  } catch (e) {
    /* never break page boot */
  }
})();<\/script>`;

// DSH 0.1.1 marks connection.isLoopback from location.hostname and therefore
// puts every settings scope into memory/unavailable mode before any RPC is
// attempted. When the operator explicitly enables the authenticated LAN
// privileged plane, adjust the connection module's exported handle as soon as
// its factory runs, before ui-settings constructs its shared settings mirror.




const AUTH_CLIENT = `<script>(function () {
  var STYLE = "box-sizing:border-box;border-radius:8px;border:1px solid #3a435e;background:#141926;color:#e6e9f2;font-size:14px;outline:none";
  var overlay = null;
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }
  function card(inner) {
    var div = document.createElement("div");
    div.id = "dsh-lan-auth-overlay";
    div.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(15,18,28,.92);display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif";
    div.innerHTML = '<div style="background:#1b2130;border:1px solid #333c54;border-radius:12px;padding:28px 32px;width:340px;color:#e6e9f2;box-shadow:0 10px 40px rgba(0,0,0,.5)">' + inner + "</div>";
    document.body.appendChild(div);
    return div;
  }
  function showSetup() {
    if (overlay) return;
    overlay = card(
      '<h2 style="margin:0 0 4px;font-size:17px;font-weight:600">DeepSeek Harness</h2>' +
      '<p style="margin:0 0 18px;font-size:13px;color:#9aa4bd">首次使用，请设置访问密码</p>' +
      '<input id="dsh-lan-auth-pass" type="password" placeholder="新密码（至少 6 位）" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<input id="dsh-lan-auth-pass2" type="password" placeholder="确认密码" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<button id="dsh-lan-auth-btn" style="width:100%;padding:10px;border-radius:8px;border:none;background:#4f6ef7;color:#fff;font-size:14px;cursor:pointer">设置密码</button>' +
      '<p id="dsh-lan-auth-err" style="margin:12px 0 0;font-size:12px;color:#ff6b6b;display:none"></p>'
    );
    var p1 = document.getElementById("dsh-lan-auth-pass");
    var p2 = document.getElementById("dsh-lan-auth-pass2");
    var err = document.getElementById("dsh-lan-auth-err");
    function submit() {
      err.style.display = "none";
      if (p1.value.length < 6) { err.textContent = "密码至少 6 位"; err.style.display = "block"; return; }
      if (p1.value !== p2.value) { err.textContent = "两次输入的密码不一致"; err.style.display = "block"; return; }
      var btn = document.getElementById("dsh-lan-auth-btn");
      btn.disabled = true; btn.textContent = "提交中…";
      fetch("/api/__lan_auth.setup", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: p1.value })
      }).then(function (r) {
        if (r.ok) { location.reload(); return; }
        r.json().then(function (j) { err.textContent = (j && j.error) || "设置失败"; err.style.display = "block"; }).catch(function () { err.style.display = "block"; });
        btn.disabled = false; btn.textContent = "设置密码";
      }).catch(function () { err.style.display = "block"; btn.disabled = false; btn.textContent = "设置密码"; });
    }
    document.getElementById("dsh-lan-auth-btn").onclick = submit;
    p2.onkeydown = function (e) { if (e.key === "Enter") submit(); };
    p1.focus();
  }
  function showLogin() {
    if (overlay) return;
    overlay = card(
      '<h2 style="margin:0 0 4px;font-size:17px;font-weight:600">DeepSeek Harness</h2>' +
      '<p style="margin:0 0 18px;font-size:13px;color:#9aa4bd">此服务需要访问密码</p>' +
      '<input id="dsh-lan-auth-pass" type="password" placeholder="访问密码" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<button id="dsh-lan-auth-btn" style="width:100%;padding:10px;border-radius:8px;border:none;background:#4f6ef7;color:#fff;font-size:14px;cursor:pointer">登录</button>' +
      '<p id="dsh-lan-auth-err" style="margin:12px 0 0;font-size:12px;color:#ff6b6b;display:none">密码错误，请重试</p>'
    );
    var input = document.getElementById("dsh-lan-auth-pass");
    var err = document.getElementById("dsh-lan-auth-err");
    function login() {
      err.style.display = "none";
      var btn = document.getElementById("dsh-lan-auth-btn");
      btn.disabled = true; btn.textContent = "登录中…";
      fetch("/api/__lan_auth.login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: input.value })
      }).then(function (r) {
        if (r.ok) { location.reload(); return; }
        err.style.display = "block";
        btn.disabled = false; btn.textContent = "登录";
      }).catch(function () { err.style.display = "block"; btn.disabled = false; btn.textContent = "登录"; });
    }
    document.getElementById("dsh-lan-auth-btn").onclick = login;
    input.onkeydown = function (e) { if (e.key === "Enter") login(); };
    input.focus();
  }
  function probe() {
    fetch("/api/__lan_auth.status", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        if (!s || s.authEnabled !== true) return;
        if (s.authenticated === true) return;
        if (s.configured === true) showLogin();
        else showSetup();
      })
      .catch(function () {});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", probe);
  else probe();
})();<\/script>`;

/**
 * When allowPrivilegedFromLan is enabled, every authenticated /api request is
 * re-targeted at loopback authority. This deliberately avoids mirroring DSH's
 * evolving privileged-method list: the plugin is intended for trusted LANs,
 * with authEnabled providing the whole-API password gate.
 */
/** Load the salted password record from disk (undefined when not set up yet). */
function loadPasswordRecord() {
  const file = passwordFile();
  if (!existsSync(file)) return void 0;
  try {
    const parsed = JSON.parse(readFileSync(file, "utf8"));
    if (typeof parsed?.salt === "string" && typeof parsed?.hash === "string") return parsed;
  } catch {
    /* corrupt file — treat as unset */
  }
  return void 0;
}

function persistPasswordRecord(record) {
  writeFileSync(passwordFile(), JSON.stringify({ v: 1, salt: record.salt, hash: record.hash }), { mode: 0o600 });
}

async function hashPassword(password, salt) {
  const derived = await scrypt(password, salt, 64);
  return derived.toString("hex");
}

async function verifyPassword(password, record) {
  if (record === void 0) return false;
  const derived = Buffer.from(await hashPassword(password, record.salt), "hex");
  const expected = Buffer.from(record.hash, "hex");
  return derived.length === expected.length && timingSafeEqual(derived, expected);
}

export function apply(ctx, config) {
  if (typeof ctx.webServer.registerUpgrade === "function" && !ctx.webServer.__lanAuthUpgradeWrapped) {
    const originalRegisterUpgrade = ctx.webServer.registerUpgrade.bind(ctx.webServer);
    ctx.webServer.registerUpgrade = (route) => {
      const originalHandler = route.handler;
      route.handler = async (req, socket, head) => {
        const loopbackHost = `127.0.0.1:${String(ctx.webServer.port ?? 3080)}`;
        const loopbackOrigin = `http://${loopbackHost}`;
        const savedHost = req.headers.host;
        const savedOrigin = req.headers.origin;
        attachDshBrowserCookie(req, savedHost || loopbackHost);
        req.headers.host = loopbackHost;
        if (req.headers.origin !== void 0) req.headers.origin = loopbackOrigin;
        if (req.headers["sec-fetch-site"] === "cross-site") req.headers["sec-fetch-site"] = "same-origin";
        attachDshBrowserCookie(req, loopbackHost);
        try { return await originalHandler(req, socket, head); }
        finally {
          req.headers.host = savedHost;
          if (savedOrigin !== void 0) req.headers.origin = savedOrigin;
        }
      };
      return originalRegisterUpgrade(route);
    };
    ctx.webServer.__lanAuthUpgradeWrapped = true;
  }

    patchDshBrowserAuth().catch((error) => {
      console.warn("[dsh-lan-access] failed to patch DSH browser auth:", error);
    });
    
    // Ensure llm-pi-ai section is properly mounted on settings so that
    // settings/describe reports llm-pi-ai to client UI, enabling custom providers.
    ctx.inject(["settings", "llm"], async (actx) => {
      try {
        const piAiModulePath = dshPiAiModule();
        if (existsSync(piAiModulePath)) {
          const mod = await import(pathToFileURL(piAiModulePath).href);
          if (mod && mod.Config && typeof actx.settings.installSection === "function") {
            const currentSections = actx.settings.describe?.({ redactSecrets: false }) ?? [];
            if (!currentSections.some(sec => sec.ns === "llm-pi-ai")) {
              actx.settings.installSection(ctx, "llm-pi-ai", mod.Config, {}, {
                setSource: () => {},
                onChange: () => {}
              });
              console.log("[dsh-lan-access] installed fallback llm-pi-ai section on settings");
            }
          }
        }
      } catch (err) {
        console.warn("[dsh-lan-access] failed to ensure llm-pi-ai on settings:", err);
      }
    });

    ctx.inject(["connection"], (cctx) => {
      const connection = cctx.connection;
      if (!connection || connection.__lanAuthWrapped) return;
      const originalAuthorize = connection.authorizeIndex?.bind(connection);
      const originalRejection = connection.requestRejection?.bind(connection);
      if (typeof originalAuthorize === "function") {
        connection.authorizeIndex = (req, res) => {
          const host = req.headers.host || `127.0.0.1:${String(ctx.webServer.port ?? 3080)}`;
          const cookie = issueDshBrowserCookie(req, 30, host);
          if (cookie) {
            attachDshBrowserCookie(req, host);
            const originalWriteHead = res.writeHead.bind(res);
            res.writeHead = function (status, headers) {
              const existing = [].concat(res.getHeader("set-cookie") ?? []);
              const incoming = headers && typeof headers === "object" && !Array.isArray(headers)
                ? [].concat(headers["set-cookie"] ?? headers["Set-Cookie"] ?? [])
                : [];
              const merged = [...existing, ...incoming, cookie].filter(Boolean);
              if (headers && typeof headers === "object" && !Array.isArray(headers)) {
                headers = { ...headers, "set-cookie": merged };
                return originalWriteHead(status, headers);
              }
              res.setHeader("set-cookie", merged);
              return originalWriteHead(status, headers);
            };
          }
          return originalAuthorize(req, res);
        };
      }
      if (typeof originalRejection === "function") {
        connection.requestRejection = (req) => {
          attachDshBrowserCookie(req, req.headers.host);
          return originalRejection(req);
        };
      }
      connection.__lanAuthWrapped = true;
    });

  // 1. Always: inject the crypto.randomUUID polyfill into every served index.html.
  ctx.effect(() => ctx.webServer.tapIndex((html) => {
    const head = html.indexOf("<head>");
    if (head === -1) return html;
    let out = html.slice(0, head + 6) + POLYFILL;
    if (config?.allowPrivilegedFromLan === true) out += LAN_OWNS_HOST;
    if (config?.authEnabled === true || typeof config?.authPassword === "string") out += AUTH_CLIENT;
    return out + html.slice(head + 6);
  }), "secure-context-polyfill: index injection");

  // ---- Optional auth gate --------------------------------------------------
  const authEnabled = config?.authEnabled === true || typeof config?.authPassword === "string";
  const configDigest = typeof config?.authPassword === "string" && config.authPassword.length > 0
    ? createHash("sha256").update(config.authPassword).digest()
    : void 0;
  let fileRecord = loadPasswordRecord();
  // SHA-256(token) -> expiresAt. Persisted under the DSH home so sessions
  // survive restarts and crash recovery; only hashes hit the disk.
  const sessions = new Map();
  const tokenHash = (token) => createHash("sha256").update(token).digest("hex");
  const persistSessions = () => {
    const now = Date.now();
    for (const [key, expiresAt] of sessions) if (expiresAt < now) sessions.delete(key);
    try {
      writeFileSync(sessionsFile(), JSON.stringify({ v: 1, sessions: [...sessions] }), { mode: 0o600 });
    } catch {
      /* best effort — in-memory sessions still work for this run */
    }
  };
  if (authEnabled) {
    try {
      const parsed = JSON.parse(readFileSync(sessionsFile(), "utf8"));
      if (typeof parsed?.v === "number" && Array.isArray(parsed.sessions)) {
        const now = Date.now();
        for (const [key, expiresAt] of parsed.sessions) {
          if (typeof key === "string" && typeof expiresAt === "number" && expiresAt >= now) sessions.set(key, expiresAt);
        }
      }
    } catch {
      /* missing or corrupt store — start with no sessions */
    }
  }
  const allowPrivileged = config?.allowPrivilegedFromLan === true;

  const readBody = async (req) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    return Buffer.concat(chunks).toString("utf8");
  };

  const tokenFromRequest = (req) => {
    const cookie = req.headers.cookie;
    if (typeof cookie !== "string") return void 0;
    for (const part of cookie.split(";")) {
      const pair = part.trim();
      if (pair.startsWith(`${AUTH_COOKIE}=`)) return pair.slice(AUTH_COOKIE.length + 1);
    }
    return void 0;
  };

  /** Trust only the actual TCP peer, never forwarding headers. */
  const isLoopbackRequest = (req) => {
    const address = req.socket?.remoteAddress;
    return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1";
  };

  const isAuthenticated = (req) => {
    // DSH already treats loopback as its privileged local authority. Keep the
    // password gate for LAN peers while allowing localhost to work normally.
    if (!authEnabled || isLoopbackRequest(req)) return true;
    const token = tokenFromRequest(req);
    if (token === void 0) return false;
    const key = tokenHash(token);
    const expiresAt = sessions.get(key);
    if (expiresAt === void 0) return false;
    if (expiresAt < Date.now()) {
      sessions.delete(key);
      persistSessions();
      return false;
    }
    return true;
  };

  const json = (res, status, payload, extraHeaders = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...extraHeaders });
    res.end(JSON.stringify(payload));
  };

  const authCookie = (token) => `${AUTH_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_TTL_MS / 1000)}`;
  const clearCookie = () => `${AUTH_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`;

  const startSession = (res) => {
    const token = randomBytes(32).toString("hex");
    sessions.set(tokenHash(token), Date.now() + AUTH_TTL_MS);
    persistSessions();
    return authCookie(token);
  };

  /** True when a password is available (config-pinned or previously set up). */
  const passwordConfigured = () => configDigest !== void 0 || fileRecord !== void 0;

  const mount = () => {
    const route = ctx.webServer.prefixes.get("/api");
    if (route === void 0) return false;

    const original = route.handler;
    const loopbackHost = `127.0.0.1:${String(ctx.webServer.port)}`;
    const loopbackOrigin = `http://127.0.0.1:${String(ctx.webServer.port)}`;
    route.handler = async (req, res) => {
      const pathname = decodeURIComponent((req.url ?? "/").split("?", 1)[0]);

      // ---- Auth endpoints (available without a session) --------------------
      if (authEnabled && pathname === "/api/__lan_auth.status") {
        json(res, 200, { authEnabled: true, configured: passwordConfigured(), authenticated: isAuthenticated(req) });
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.setup") {
        if (passwordConfigured()) {
          json(res, 409, { ok: false, error: "password already configured" });
          return;
        }
        let password;
        try {
          password = JSON.parse(await readBody(req))?.password;
        } catch {
          password = void 0;
        }
        if (typeof password !== "string" || password.length < 6) {
          json(res, 400, { ok: false, error: "password must be at least 6 characters" });
          return;
        }
        const salt = randomBytes(16).toString("hex");
        const record = { salt, hash: await hashPassword(password, salt) };
        persistPasswordRecord(record);
        fileRecord = record;
        json(res, 200, { ok: true }, { "set-cookie": [startSession(res), issueDshBrowserCookie(req)].filter(Boolean) });
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.login") {
        if (!passwordConfigured()) {
          json(res, 409, { ok: false, error: "no password configured yet" });
          return;
        }
        let password;
        try {
          password = JSON.parse(await readBody(req))?.password;
        } catch {
          password = void 0;
        }
        const ok = typeof password === "string" && (
          configDigest !== void 0 ? timingSafeEqual(createHash("sha256").update(password).digest(), configDigest)
            : await verifyPassword(password, fileRecord)
        );
        if (!ok) {
          json(res, 401, { ok: false, error: "invalid password" });
          return;
        }
        json(res, 200, { ok: true }, { "set-cookie": [startSession(res), issueDshBrowserCookie(req)].filter(Boolean) });
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.logout") {
        const token = tokenFromRequest(req);
        if (token !== void 0) {
          sessions.delete(tokenHash(token));
          persistSessions();
        }
        json(res, 200, { ok: true }, { "set-cookie": clearCookie() });
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.changePassword") {
        if (!isAuthenticated(req)) {
          json(res, 401, { ok: false, error: "unauthorized" });
          return;
        }
        if (configDigest !== void 0) {
          json(res, 409, { ok: false, error: "password is pinned in profile config; edit authPassword instead" });
          return;
        }
        let oldPassword;
        let newPassword;
        try {
          const body = JSON.parse(await readBody(req));
          oldPassword = body?.oldPassword;
          newPassword = body?.newPassword;
        } catch {
          oldPassword = newPassword = void 0;
        }
        if (typeof newPassword !== "string" || newPassword.length < 6) {
          json(res, 400, { ok: false, error: "new password must be at least 6 characters" });
          return;
        }
        if (!(await verifyPassword(oldPassword, fileRecord))) {
          json(res, 401, { ok: false, error: "current password is incorrect" });
          return;
        }
        const salt = randomBytes(16).toString("hex");
        const record = { salt, hash: await hashPassword(newPassword, salt) };
        persistPasswordRecord(record);
        fileRecord = record;
        sessions.clear(); // force every device to re-login
        persistSessions();
        json(res, 200, { ok: true }, { "set-cookie": [startSession(res), issueDshBrowserCookie(req)].filter(Boolean) });
        return;
      }

      // ---- Whole-API auth gate ---------------------------------------------
      if (authEnabled && !isAuthenticated(req)) {
        json(res, 401, { ok: false, error: "unauthorized", code: "lan-auth-required" });
        return;
      }

      // ---- Trusted-LAN API bypass (re-target all authenticated API calls) ---
      // Unknown/new DSH methods are included automatically, preventing the
      // compatibility drift caused by a duplicated privileged-method list.
      if (allowPrivileged && pathname.startsWith("/api/")) {
        const savedHost = req.headers.host;
        const savedOrigin = req.headers.origin;
        attachDshBrowserCookie(req, savedHost || loopbackHost);
        req.headers.host = loopbackHost;
        if (req.headers.origin !== void 0) req.headers.origin = loopbackOrigin;
        if (req.headers["sec-fetch-site"] === "cross-site") req.headers["sec-fetch-site"] = "same-origin";
        attachDshBrowserCookie(req, loopbackHost);
        try {
          return await original(req, res);
        } finally {
          req.headers.host = savedHost;
          if (savedOrigin !== void 0) req.headers.origin = savedOrigin;
        }
      }
      return original(req, res);
    };
    ctx.effect(() => () => {
      route.handler = original;
    }, "lan-access: restore /api route handler");

    // ---- Wrap WebSocket upgrade routes -------------------------------------
    if (authEnabled) {
      const wrapUpgrades = () => {
        for (const upgradeRoute of ctx.webServer.upgrades.values()) {
          if (upgradeRoute.__lanAuthWrapped) continue;
          const originalUpgrade = upgradeRoute.handler;
          upgradeRoute.handler = async (req, socket, head) => {
            if (!isAuthenticated(req)) {
              socket.destroy();
              return;
            }
            // Keep WebSocket downlinks under the same trusted-LAN authority as
            // authenticated HTTP /api calls. Session/workspace updates flow on
            // /api/events.mux and /api/events.host, not through unary HTTP.
            if (allowPrivileged && new URL(req.url ?? "/", "http://dsh.local").pathname.startsWith("/api/")) {
              const savedHost = req.headers.host;
              const savedOrigin = req.headers.origin;
              attachDshBrowserCookie(req, savedHost || loopbackHost);
              req.headers.host = loopbackHost;
              if (req.headers.origin !== void 0) req.headers.origin = loopbackOrigin;
              if (req.headers["sec-fetch-site"] === "cross-site") req.headers["sec-fetch-site"] = "same-origin";
              attachDshBrowserCookie(req, loopbackHost);
              try {
                return await originalUpgrade(req, socket, head);
              } finally {
                req.headers.host = savedHost;
                if (savedOrigin !== void 0) req.headers.origin = savedOrigin;
              }
            }
            return originalUpgrade(req, socket, head);
          };
          upgradeRoute.__lanAuthWrapped = true;
        }
      };
      wrapUpgrades();
      const timer = setInterval(wrapUpgrades, 1000);
      setTimeout(() => clearInterval(timer), 30000);
      ctx.effect(() => clearInterval(timer), "lan-access: upgrade auth wrap timer");
    }
    return true;
  };

  if (!mount()) {
    // /api route not mounted yet (connection row ordering) — wait for it.
    ctx.on("internal/service", () => {
      if (ctx.webServer.prefixes.has("/api")) mount();
    });
  }
}
