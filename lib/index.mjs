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
 * 3. authPassword (opt-in). A simple password gate for the whole /api plane
 *    (HTTP + WebSocket), implemented as a session-cookie auth layer inside
 *    this plugin — DSH itself ships no web authentication ("until a real
 *    authentication layer exists"). Configure authPassword to require login
 *    before any API call works; an injected client script shows a login
 *    overlay on first load. HttpOnly + SameSite=Strict cookie; tokens live
 *    in memory (lost on restart) and expire after AUTH_TTL_MS.
 *    This is a convenience gate for trusted LANs, NOT a hardened security
 *    boundary: credentials travel over plain HTTP, and the session cookie is
 *    scoped to this origin only.
 */
import { createHash, randomBytes } from "node:crypto";

export const name = "secure-context-polyfill";

export const inject = ["webServer"];

/** Session lifetime for the optional authPassword gate. */
const AUTH_TTL_MS = 12 * 60 * 60 * 1000;
const AUTH_COOKIE = "dsh_lan_auth";

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
  function probe() {
    try {
      fetch("/api/workspace.list", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ type: "client-request", rpcId: "lan-auth-probe", method: "workspace.list", payload: {} })
      }).then(function (r) { if (r.status === 401) showLogin(); }).catch(function () {});
    } catch (e) {}
  }
  function showLogin() {
    if (document.getElementById("dsh-lan-auth-overlay")) return;
    var div = document.createElement("div");
    div.id = "dsh-lan-auth-overlay";
    div.style.cssText = "position:fixed;inset:0;z-index:2147483647;background:rgba(15,18,28,.92);display:flex;align-items:center;justify-content:center;font-family:system-ui,-apple-system,sans-serif";
    div.innerHTML = '<div style="background:#1b2130;border:1px solid #333c54;border-radius:12px;padding:28px 32px;width:320px;color:#e6e9f2;box-shadow:0 10px 40px rgba(0,0,0,.5)"><h2 style="margin:0 0 4px;font-size:17px;font-weight:600">DeepSeek Harness</h2><p style="margin:0 0 18px;font-size:13px;color:#9aa4bd">此服务需要访问密码</p><input id="dsh-lan-auth-pass" type="password" placeholder="访问密码" style="width:100%;box-sizing:border-box;padding:10px 12px;border-radius:8px;border:1px solid #3a435e;background:#141926;color:#e6e9f2;font-size:14px;margin-bottom:12px;outline:none"><button id="dsh-lan-auth-btn" style="width:100%;padding:10px;border-radius:8px;border:none;background:#4f6ef7;color:#fff;font-size:14px;cursor:pointer">登录</button><p id="dsh-lan-auth-err" style="margin:12px 0 0;font-size:12px;color:#ff6b6b;display:none">密码错误，请重试</p></div>';
    document.body.appendChild(div);
    var input = document.getElementById("dsh-lan-auth-pass");
    var btn = document.getElementById("dsh-lan-auth-btn");
    var err = document.getElementById("dsh-lan-auth-err");
    function login() {
      err.style.display = "none";
      btn.disabled = true; btn.textContent = "登录中…";
      fetch("/api/__lan_auth.login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ password: input.value })
      }).then(function (r) {
        if (r.ok) { location.reload(); return; }
        err.style.display = "block";
        btn.disabled = false; btn.textContent = "登录";
      }).catch(function () {
        err.style.display = "block";
        btn.disabled = false; btn.textContent = "登录";
      });
    }
    btn.onclick = login;
    input.onkeydown = function (e) { if (e.key === "Enter") login(); };
    input.focus();
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

/** Digest the configured password once (constant-time compare at request time). */
function passwordDigest(password) {
  return createHash("sha256").update(password).digest();
}

export function apply(ctx, config) {
  // 1. Always: inject the crypto.randomUUID polyfill into every served index.html.
  ctx.effect(() => ctx.webServer.tapIndex((html) => {
    const head = html.indexOf("<head>");
    if (head === -1) return html;
    let out = html.slice(0, head + 6) + POLYFILL;
    if (config?.authPassword) out += AUTH_CLIENT;
    return out + html.slice(head + 6);
  }), "secure-context-polyfill: index injection");

  // Session store for the optional auth gate (in-memory; lost on restart).
  const sessions = new Map(); // token -> expiresAt
  const authEnabled = typeof config?.authPassword === "string" && config.authPassword.length > 0;
  const expectedDigest = authEnabled ? passwordDigest(config.authPassword) : void 0;

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

  const mount = () => {
    const route = ctx.webServer.prefixes.get("/api");
    if (route === void 0) return false;

    // ---- Wrap the /api HTTP route ----------------------------------------
    const original = route.handler;
    const loopbackHost = `127.0.0.1:${String(ctx.webServer.port)}`;
    const loopbackOrigin = `http://127.0.0.1:${String(ctx.webServer.port)}`;
    const allowPrivileged = config?.allowPrivilegedFromLan === true;
    route.handler = async (req, res) => {
      const pathname = decodeURIComponent((req.url ?? "/").split("?", 1)[0]);

      // Auth endpoints (always available when auth is enabled).
      if (authEnabled && pathname === "/api/__lan_auth.login") {
        let ok = false;
        try {
          const body = JSON.parse(await readBody(req));
          ok = typeof body?.password === "string" && passwordDigest(body.password).equals(expectedDigest);
        } catch {
          ok = false;
        }
        if (!ok) {
          res.writeHead(401, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "invalid password" }));
          return;
        }
        const token = randomBytes(32).toString("hex");
        sessions.set(token, Date.now() + AUTH_TTL_MS);
        res.writeHead(200, {
          "content-type": "application/json",
          "set-cookie": `${AUTH_COOKIE}=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${Math.floor(AUTH_TTL_MS / 1000)}`
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }
      if (authEnabled && pathname === "/api/__lan_auth.logout") {
        const token = tokenFromRequest(req);
        if (token !== void 0) sessions.delete(token);
        res.writeHead(200, {
          "content-type": "application/json",
          "set-cookie": `${AUTH_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0`
        });
        res.end(JSON.stringify({ ok: true }));
        return;
      }

      // Whole-API auth gate.
      if (authEnabled && !isAuthenticated(req)) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "unauthorized", code: "lan-auth-required" }));
        return;
      }

      // Privileged-methods LAN bypass (re-target at loopback authority).
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

    // ---- Wrap WebSocket upgrade routes -----------------------------------
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
