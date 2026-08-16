/**
 * dsh-lan-access — host plugin entry.
 *
 * Two optional fixes for running the DSH Web GUI over a plain-http LAN IP
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
 */
export const name = "secure-context-polyfill";

export const inject = ["webServer"];

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

export function apply(ctx, config) {
  // 1. Always: inject the crypto.randomUUID polyfill into every served index.html.
  ctx.effect(() => ctx.webServer.tapIndex((html) => {
    const head = html.indexOf("<head>");
    if (head === -1) return html;
    return html.slice(0, head + 6) + POLYFILL + html.slice(head + 6);
  }), "secure-context-polyfill: index injection");

  // 2. Opt-in: let privileged methods work from trusted LAN hosts.
  // The /api route handler is wrapped so that, for privileged methods, the
  // request is re-targeted at the loopback authority before the original
  // pipeline (trust fence -> bridge -> rpc dispatch) runs. Everything else is
  // untouched. The wrap is registered lazily after the connection row mounts
  // its /api route, and is restored on dispose.
  if (config?.allowPrivilegedFromLan === true) {
    const mount = () => {
      const route = ctx.webServer.prefixes.get("/api");
      if (route === void 0) return false;
      const original = route.handler;
      const loopbackHost = `127.0.0.1:${String(ctx.webServer.port)}`;
      const loopbackOrigin = `http://127.0.0.1:${String(ctx.webServer.port)}`;
      route.handler = async (req, res) => {
        const pathname = decodeURIComponent((req.url ?? "/").split("?", 1)[0]);
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
        return original(req, res);
      };
      ctx.effect(() => () => {
        route.handler = original;
      }, "lan-access: restore /api route handler");
      return true;
    };
    if (!mount()) {
      // /api route not mounted yet (connection row ordering) — wait for it.
      ctx.on("internal/service", () => {
        if (ctx.webServer.prefixes.has("/api")) mount();
      });
    }
  }
}
