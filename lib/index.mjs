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
 * 2. allowPrivilegedFromLan (opt-in, default false). DSH gates a set of
 *    "privileged" methods (settings.*, credentials.*, agentPreset.*,
 *    host.pickDirectory, host.openPath, llm.discoverModels) to loopback by
 *    design, because the LAN trust fence is not authentication. When you
 *    explicitly set allowPrivilegedFromLan: true, requests to those methods
 *    from a trusted LAN host are re-dispatched to the loopback authority so
 *    the settings / presets / permissions pages work from LAN devices.
 *    Enable only on trusted networks.
 *
 * 3. authEnabled / authPassword (opt-in). A password gate for the whole /api
 *    plane (HTTP + WebSocket), because DSH itself ships no web authentication
 *    ("until a real authentication layer exists"). Password sources:
 *      - config.authPassword — set it to pin a fixed password in the profile,
 *        or
 *      - first-use setup — with authEnabled: true (and no authPassword), the
 *        first visitor is asked to create a password, which is stored salted
 *        (scrypt) at $DSH_HOME/lan-access-password.json and survives restarts;
 *        it can then be changed from the web UI (signed-in change dialog).
 *    Sessions are HttpOnly + SameSite=Strict cookies with an in-memory token
 *    store (12 h TTL, lost on restart).
 *    This is a convenience gate for trusted LANs, NOT a hardened security
 *    boundary: credentials travel over plain HTTP, and the password is shared
 *    by everyone who is granted access.
 */
import { createHash, randomBytes, scrypt as scryptCb, timingSafeEqual } from "node:crypto";
import { promisify } from "node:util";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { homedir } from "node:os";

const scrypt = promisify(scryptCb);

export const name = "secure-context-polyfill";

export const inject = ["webServer"];

/** Session lifetime for the optional auth gate. */
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_COOKIE = "dsh_lan_auth";

/** Password store under the DSH home. */
function passwordFile() {
  const home = process.env.DSH_HOME ?? join(homedir(), ".dsh");
  return join(home, "lan-access-password.json");
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
  function showChangePassword() {
    overlay = card(
      '<h2 style="margin:0 0 4px;font-size:17px;font-weight:600">修改访问密码</h2>' +
      '<p style="margin:0 0 18px;font-size:13px;color:#9aa4bd">修改后其他已登录设备需重新登录</p>' +
      '<input id="dsh-lan-auth-old" type="password" placeholder="当前密码" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<input id="dsh-lan-auth-pass" type="password" placeholder="新密码（至少 6 位）" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<input id="dsh-lan-auth-pass2" type="password" placeholder="确认新密码" style="width:100%;padding:10px 12px;' + STYLE + ';margin-bottom:12px">' +
      '<button id="dsh-lan-auth-btn" style="width:100%;padding:10px;border-radius:8px;border:none;background:#4f6ef7;color:#fff;font-size:14px;cursor:pointer">确认修改</button>' +
      '<p id="dsh-lan-auth-err" style="margin:12px 0 0;font-size:12px;color:#ff6b6b;display:none"></p>'
    );
    var old = document.getElementById("dsh-lan-auth-old");
    var p1 = document.getElementById("dsh-lan-auth-pass");
    var p2 = document.getElementById("dsh-lan-auth-pass2");
    var err = document.getElementById("dsh-lan-auth-err");
    function submit() {
      err.style.display = "none";
      if (p1.value.length < 6) { err.textContent = "新密码至少 6 位"; err.style.display = "block"; return; }
      if (p1.value !== p2.value) { err.textContent = "两次输入的新密码不一致"; err.style.display = "block"; return; }
      var btn = document.getElementById("dsh-lan-auth-btn");
      btn.disabled = true; btn.textContent = "提交中…";
      fetch("/api/__lan_auth.changePassword", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ oldPassword: old.value, newPassword: p1.value })
      }).then(function (r) {
        if (r.ok) { location.reload(); return; }
        r.json().then(function (j) { err.textContent = (j && j.error) || "修改失败"; err.style.display = "block"; }).catch(function () { err.style.display = "block"; });
        btn.disabled = false; btn.textContent = "确认修改";
      }).catch(function () { err.style.display = "block"; btn.disabled = false; btn.textContent = "确认修改"; });
    }
    document.getElementById("dsh-lan-auth-btn").onclick = submit;
    p2.onkeydown = function (e) { if (e.key === "Enter") submit(); };
    old.focus();
  }
  function addChangePasswordEntry() {
    var btn = document.createElement("button");
    btn.id = "dsh-lan-auth-change";
    btn.textContent = "修改密码";
    btn.style.cssText = "position:fixed;right:16px;bottom:16px;z-index:2147483000;padding:8px 14px;border-radius:8px;border:none;background:#2a3350;color:#b9c3dd;font-size:12px;cursor:pointer;font-family:system-ui,sans-serif";
    btn.onclick = function () { overlay = null; showChangePassword(); };
    document.body.appendChild(btn);
  }
  function probe() {
    fetch("/api/__lan_auth.status", { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })
      .then(function (r) { return r.json(); })
      .then(function (s) {
        if (!s || s.authEnabled !== true) return;
        if (s.authenticated === true) { addChangePasswordEntry(); return; }
        if (s.configured === true) showLogin();
        else showSetup();
      })
      .catch(function () {});
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", probe);
  else probe();
})();<\/script>`;

/** Mirror of dsh-client-connection's PRIVILEGED_METHODS (loopback-gated by design). */
const PRIVILEGED_METHODS = new Set([
  "agentPreset.read",
  "agentPreset.copy",
  "agentPreset.openDocument",
  "agentPreset.remove",
  "host.pickDirectory",
  "host.openPath",
  "settings.describe",
  "settings.openDocument",
  "settings.update",
  "settings.replace",
  "settings.mutate",
  "credentials.describe",
  "credentials.set",
  "credentials.unset",
  "llm.discoverModels"
]);

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
  // 1. Always: inject the crypto.randomUUID polyfill into every served index.html.
  ctx.effect(() => ctx.webServer.tapIndex((html) => {
    const head = html.indexOf("<head>");
    if (head === -1) return html;
    let out = html.slice(0, head + 6) + POLYFILL;
    if (config?.authEnabled === true || typeof config?.authPassword === "string") out += AUTH_CLIENT;
    return out + html.slice(head + 6);
  }), "secure-context-polyfill: index injection");

  // ---- Optional auth gate --------------------------------------------------
  const authEnabled = config?.authEnabled === true || typeof config?.authPassword === "string";
  const configDigest = typeof config?.authPassword === "string" && config.authPassword.length > 0
    ? createHash("sha256").update(config.authPassword).digest()
    : void 0;
  let fileRecord = loadPasswordRecord();
  const sessions = new Map(); // token -> expiresAt
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

  const isAuthenticated = (req) => {
    if (!authEnabled) return true;
    const token = tokenFromRequest(req);
    if (token === void 0) return false;
    const expiresAt = sessions.get(token);
    if (expiresAt === void 0) return false;
    if (expiresAt < Date.now()) {
      sessions.delete(token);
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
    sessions.set(token, Date.now() + AUTH_TTL_MS);
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
        json(res, 200, { ok: true }, { "set-cookie": startSession(res) });
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
        json(res, 200, { ok: true }, { "set-cookie": startSession(res) });
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.logout") {
        const token = tokenFromRequest(req);
        if (token !== void 0) sessions.delete(token);
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
        json(res, 200, { ok: true }, { "set-cookie": startSession(res) });
        return;
      }

      // ---- Whole-API auth gate ---------------------------------------------
      if (authEnabled && !isAuthenticated(req)) {
        json(res, 401, { ok: false, error: "unauthorized", code: "lan-auth-required" });
        return;
      }

      // ---- Privileged-methods LAN bypass (re-target at loopback authority) --
      if (allowPrivileged) {
        const method = pathname.startsWith("/api/") ? pathname.slice(5) : void 0;
        if (method !== void 0 && PRIVILEGED_METHODS.has(method)) {
          const savedHost = req.headers.host;
          const savedOrigin = req.headers.origin;
          req.headers.host = loopbackHost;
          if (req.headers.origin !== void 0) req.headers.origin = loopbackOrigin;
          try {
            return await original(req, res);
          } finally {
            req.headers.host = savedHost;
            if (savedOrigin !== void 0) req.headers.origin = savedOrigin;
          }
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
          upgradeRoute.handler = (req, socket, head) => {
            if (!isAuthenticated(req)) {
              socket.destroy();
              return;
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
