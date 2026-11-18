// Cloudflare Worker: WebSocket -> TCP мост до датацентра Telegram.
// Клиент подключается к wss://<ваш-воркер>/apiws?dst=<IP датацентра>
// и передаёт по WebSocket «сырой» поток MTProto (obfuscated2); воркер открывает TCP на dst:443.
import { connect } from "cloudflare:sockets";

const ALLOWED = /^(149\.154\.(16[0-9]|17[0-9])\.\d{1,3}|91\.108\.\d{1,3}\.\d{1,3}|91\.105\.192\.\d{1,3}|95\.161\.\d{1,3}\.\d{1,3})$/;

export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname !== "/apiws" || request.headers.get("Upgrade") !== "websocket") {
      return new Response("ok", { status: 200 });
    }
    const dst = url.searchParams.get("dst") || "";
    if (!ALLOWED.test(dst)) return new Response("bad dst", { status: 400 });

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    server.accept();

    const tcp = connect({ hostname: dst, port: 443 });
    const writer = tcp.writable.getWriter();

    server.addEventListener("message", (ev) => {
      const d = ev.data;
      writer.write(d instanceof ArrayBuffer ? new Uint8Array(d) : new TextEncoder().encode(d)).catch(() => server.close());
    });
    server.addEventListener("close", () => { try { tcp.close(); } catch (_) {} });
    server.addEventListener("error", () => { try { tcp.close(); } catch (_) {} });

    tcp.readable.pipeTo(new WritableStream({
      write(chunk) { server.send(chunk); },
      close() { try { server.close(); } catch (_) {} },
      abort() { try { server.close(); } catch (_) {} },
    })).catch(() => { try { server.close(); } catch (_) {} });

    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: { "Sec-WebSocket-Protocol": "binary" },
    });
  },
};
