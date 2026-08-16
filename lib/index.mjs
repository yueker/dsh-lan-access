/**
 * dsh-secure-context-polyfill — host plugin entry.
 *
 * Injects a <script> into every served index.html that defines
 * crypto.randomUUID() on origins where the browser omits it.
 *
 * Why: Chrome exposes Crypto.randomUUID only in secure contexts. Accessing
 * the Web GUI over a plain-http LAN IP (e.g. http://192.168.2.102:3080) is
 * NOT a secure context, so crypto.randomUUID is undefined there. The client
 * connection bundle mints RPC ids with it (AbstractApiClient.mintRpcId), so
 * the connection handshake rejects before any request is sent and the GUI is
 * stuck in an infinite "connection lost, retry" loop with no sessions or
 * workspace visible. crypto.getRandomValues IS available on insecure origins,
 * so a UUID v4 built from it restores full functionality.
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

export function apply(ctx) {
  ctx.effect(() => ctx.webServer.tapIndex((html) => {
    const head = html.indexOf("<head>");
    if (head === -1) return html;
    return html.slice(0, head + 6) + POLYFILL + html.slice(head + 6);
  }), "secure-context-polyfill: index injection");
}
