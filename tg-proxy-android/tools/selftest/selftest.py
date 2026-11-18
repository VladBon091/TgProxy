#!/usr/bin/env python3
"""
Самопроверка ядра прокси на локальных фейковых серверах.

Независимая реализация «клиента Telegram» (obfuscated2 + секрет) и «датацентра»
(WebSocket поверх TLS / голый TCP) на Python. Ядро на Kotlin запускается как
отдельный процесс (Harness.kt) и стоит между ними.

Это проверка протокола и логики маршрутов. Она НЕ проверяет, пропускает ли
ваш провайдер реальные адреса Telegram — для этого есть кнопка «Диагностика» в приложении.
"""
import os, sys, ssl, socket, threading, struct, hashlib, base64, subprocess, time, random, queue
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

OUT = os.environ.get("OUT", "/tmp/tgproxy-selftest-out")
STDLIB = os.environ.get("STDLIB", "/opt/gradle/lib/kotlin-stdlib-2.0.21.jar")
CERT = os.environ["CERT"]
KEY = os.environ["KEY"]
WS_PORT = int(os.environ.get("WS_PORT", "18443"))
TCP_PORT = int(os.environ.get("TCP_PORT", "18444"))

TAG_ABR, TAG_INT, TAG_PAD = b"\xef\xef\xef\xef", b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd"
REQ_PQ = bytes.fromhex("f18e7ebe")   # 0xbe7e8ef1 LE
RES_PQ = bytes.fromhex("63241605")   # 0x05162463 LE


def ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv)).encryptor()


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError("closed")
        buf += chunk
    return bytes(buf)


# ---------------------------------------------------------------- packets
def frame_packet(payload, tag):
    if tag == TAG_ABR:
        w = len(payload) // 4
        return (bytes([w]) if w < 0x7f else b"\x7f" + w.to_bytes(3, "little")) + payload
    return struct.pack("<I", len(payload)) + payload


def parse_packets(buf, tag):
    """-> (list of (full_packet_bytes, payload), consumed)"""
    out, pos = [], 0
    while True:
        if tag == TAG_ABR:
            if len(buf) - pos < 1: break
            f = buf[pos] & 0x7f
            if f == 0x7f:
                if len(buf) - pos < 4: break
                n, hdr = int.from_bytes(buf[pos + 1:pos + 4], "little") * 4, 4
            else:
                n, hdr = f * 4, 1
        else:
            if len(buf) - pos < 4: break
            n, hdr = struct.unpack_from("<I", buf, pos)[0] & 0x7fffffff, 4
        if len(buf) - pos < hdr + n: break
        out.append((bytes(buf[pos:pos + hdr + n]), bytes(buf[pos + hdr:pos + hdr + n])))
        pos += hdr + n
    return out, pos


# ---------------------------------------------------------------- fake DC
class FakeDC:
    """kind: 'ws' (TLS/plain WS, sniffed) | 'tcp'. mode: 'good' | 'blackhole'."""

    def __init__(self, host, port, kind, mode="good"):
        self.kind, self.mode, self.host, self.port = kind, mode, host, port
        self.seen, self.violations = [], []
        self.lock = threading.Lock()
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(128)
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(CERT, KEY)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            try:
                c, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def note(self, **kw):
        with self.lock:
            self.seen.append(kw)

    def violate(self, msg):
        with self.lock:
            self.violations.append(msg)

    # --- WS plumbing
    def _ws_handshake(self, conn):
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk: raise EOFError
            data += chunk
        head = data.split(b"\r\n\r\n")[0].decode()
        lines = head.split("\r\n")
        path = lines[0].split(" ")[1]
        hdr = {l.split(":", 1)[0].strip().lower(): l.split(":", 1)[1].strip() for l in lines[1:]}
        assert hdr.get("upgrade", "").lower() == "websocket", "no Upgrade"
        assert hdr.get("sec-websocket-version") == "13"
        assert "binary" in hdr.get("sec-websocket-protocol", "")
        key = hdr["sec-websocket-key"]
        acc = base64.b64encode(hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                      f"Sec-WebSocket-Accept: {acc}\r\nSec-WebSocket-Protocol: binary\r\n\r\n").encode())
        return path, hdr

    @staticmethod
    def _ws_read(conn):
        while True:
            h = conn.recv(2)
            if len(h) < 2: return None
            op, masked, n = h[0] & 0x0f, h[1] & 0x80, h[1] & 0x7f
            if n == 126: n = struct.unpack(">H", recv_exact(conn, 2))[0]
            elif n == 127: n = struct.unpack(">Q", recv_exact(conn, 8))[0]
            if not masked: raise AssertionError("client frame not masked")
            mask = recv_exact(conn, 4)
            data = bytearray(recv_exact(conn, n))
            for i in range(n): data[i] ^= mask[i & 3]
            if op == 8: return None
            if op == 9: continue
            return bytes(data)

    @staticmethod
    def _ws_send(conn, data):
        n = len(data)
        hdr = bytes([0x82]) + (bytes([n]) if n < 126 else b"\x7e" + struct.pack(">H", n) if n <= 0xffff else b"\x7f" + struct.pack(">Q", n))
        conn.sendall(hdr + data)

    # --- connection handler
    def _handle(self, conn):
        try:
            conn.settimeout(60)
            if self.kind == "ws":
                if conn.recv(1, socket.MSG_PEEK) == b"\x16":
                    conn = self.ctx.wrap_socket(conn, server_side=True)
                path, hdr = self._ws_handshake(conn)
                worker = "?dst=" in path
                recv = lambda: self._ws_read(conn)
                send = lambda b: self._ws_send(conn, b)
                check_frames = not worker
            else:
                path, worker, check_frames, hdr = "tcp", False, False, {}
                def recv():
                    d = conn.recv(65536)
                    return d or None
                send = conn.sendall
            if self.mode == "blackhole":
                while recv() is not None: pass
                return
            self._engine(recv, send, path, check_frames)
        except (EOFError, ConnectionError, ssl.SSLError, socket.timeout, OSError):
            pass
        except Exception as e:   # noqa
            self.violate(f"handler error: {e!r}")
        finally:
            try: conn.close()
            except Exception: pass

    def _engine(self, recv, send, path, check_frames):
        first = recv()
        if first is None: return
        buf = bytearray(first)
        while len(buf) < 64:
            m = recv()
            if m is None: return
            buf += m
        init, rest = bytes(buf[:64]), bytes(buf[64:])
        if check_frames and len(first) != 64:
            self.violate(f"first WS frame is {len(first)} bytes, expected the 64-byte init alone")
        dec = ctr(init[8:40], init[40:56])
        plain = dec.update(init)
        tag = plain[56:60]
        dc = struct.unpack("<h", plain[60:62])[0]
        if tag not in (TAG_ABR, TAG_INT, TAG_PAD):
            self.violate(f"bad tag {tag.hex()}"); return
        rev = init[8:56][::-1]
        enc = ctr(rev[:32], rev[32:48])
        self.note(dc=dc, tag=tag, path=path)
        stream = bytearray()

        def process(chunk):
            pt = dec.update(chunk)
            if check_frames:
                pk, used = parse_packets(pt, tag)
                if len(pk) != 1 or used != len(pt):
                    self.violate(f"WS frame carries {len(pk)} packets (used {used}/{len(pt)})")
            stream.extend(pt)
            pk, used = parse_packets(bytes(stream), tag)
            del stream[:used]
            for full, payload in pk:
                if len(payload) >= 24 and payload[:8] == b"\0" * 8 and payload[20:24] == REQ_PQ:
                    nonce = payload[24:40]
                    body = (b"\0" * 8 + struct.pack("<Q", int(time.time()) << 32 | 1) + struct.pack("<I", 52)
                            + RES_PQ + nonce + os.urandom(16) + os.urandom(32))
                    reply = frame_packet(body, tag)
                else:
                    reply = full
                send(enc.update(reply))

        if rest: process(rest)
        while True:
            m = recv()
            if m is None: return
            process(m)

    def close(self):
        self.sock.close()


# ---------------------------------------------------------------- fake Telegram client
class TgClient:
    def __init__(self, port, secret, dc, tag=TAG_ABR):
        self.tag = tag
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=30)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        while True:
            init = bytearray(os.urandom(64))
            if init[0] == 0xef or bytes(init[:4]) in (b"HEAD", b"POST", b"GET ", b"OPTI", b"\xdd" * 4, b"\xee" * 4): continue
            if init[4:8] == b"\0\0\0\0": continue
            break
        init[56:60] = tag
        init[60:62] = struct.pack("<h", dc)
        ek = hashlib.sha256(bytes(init[8:40]) + secret).digest()
        self.enc = ctr(ek, bytes(init[40:56]))
        e = self.enc.update(bytes(init))
        wire = bytes(init[:56]) + e[56:64]
        rev = bytes(init[8:56])[::-1]
        dk = hashlib.sha256(rev[:32] + secret).digest()
        self.dec = ctr(dk, rev[32:48])
        self.sock.sendall(wire)

    def send_payloads(self, payloads, slice_max=None):
        data = b"".join(frame_packet(p, self.tag) for p in payloads)
        data = self.enc.update(data)
        if not slice_max:
            self.sock.sendall(data); return
        i = 0
        while i < len(data):
            n = random.randint(1, slice_max)
            self.sock.sendall(data[i:i + n]); i += n

    def _read(self, n):
        return self.dec.update(recv_exact(self.sock, n))

    def recv_payload(self):
        if self.tag == TAG_ABR:
            b = self._read(1)[0] & 0x7f
            n = int.from_bytes(self._read(3), "little") * 4 if b == 0x7f else b * 4
        else:
            n = struct.unpack("<I", self._read(4))[0] & 0x7fffffff
        return self._read(n)

    def close(self):
        try: self.sock.close()
        except Exception: pass


def req_pq_payload(nonce):
    return b"\0" * 8 + struct.pack("<Q", int(time.time()) << 32) + struct.pack("<I", 20) + REQ_PQ + nonce


def check_res_pq(payload, nonce):
    assert payload[20:24] == RES_PQ, f"not resPQ: {payload[:32].hex()}"
    assert payload[24:40] == nonce, "nonce mismatch"


# ---------------------------------------------------------------- Kotlin harness process
class Proxy:
    def __init__(self, mode, secret):
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        self.p = subprocess.Popen(
            ["java", "-cp", f"{OUT}:{STDLIB}", "app.tgproxy.selftest.HarnessKt", mode, str(self.port), secret.hex(),
             str(WS_PORT), str(TCP_PORT), CERT],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        self.lines, self.q = [], queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        deadline = time.time() + 20
        while time.time() < deadline:
            try:
                l = self.q.get(timeout=1)
            except queue.Empty:
                continue
            if l.startswith("READY"): return
        raise RuntimeError("proxy did not start: " + "\n".join(self.lines))

    def _pump(self):
        for l in self.p.stdout:
            l = l.rstrip("\n"); self.lines.append(l); self.q.put(l)

    def stop(self):
        try: self.p.stdin.close()
        except Exception: pass
        try: self.p.wait(timeout=5)
        except Exception: self.p.kill()

    def log_text(self):
        return "\n".join(self.lines)


# ---------------------------------------------------------------- scenarios
SECRET = bytes.fromhex("00112233445566778899aabbccddeeff")
results = []


def check(name, fn):
    t = time.time()
    try:
        fn()
        results.append((name, True, "%.1fs" % (time.time() - t)))
        print(f"  PASS  {name}  ({time.time() - t:.1f}s)")
    except Exception as e:
        import traceback
        results.append((name, False, repr(e)))
        print(f"  FAIL  {name}: {e!r}")
        traceback.print_exc()


def handshake_and_echo(port, dc, tag, big=False):
    c = TgClient(port, SECRET, dc, tag)
    try:
        nonce = os.urandom(16)
        c.send_payloads([req_pq_payload(nonce)])
        check_res_pq(c.recv_payload(), nonce)
        # эхо-пакеты, склеенные и нарезанные в случайных местах
        n = 400 if big else 40
        payloads = [os.urandom(random.choice([4, 8, 16, 64, 512, 4096, 16000, 130000 if big and random.random() < 0.02 else 20]) // 4 * 4) for _ in range(n)]
        t = threading.Thread(target=c.send_payloads, args=(payloads, 3000))
        t.start()
        for i, p in enumerate(payloads):
            got = c.recv_payload()
            assert got == p, f"echo mismatch at packet {i} (len {len(p)} vs {len(got)})"
        t.join()
    finally:
        c.close()


def run_mode_basic(mode, dcs_tags, servers):
    px = Proxy(mode, SECRET)
    try:
        for dc, tag, big in dcs_tags:
            handshake_and_echo(px.port, dc, tag, big)
        return px
    finally:
        px.stop()


def main():
    ws_good = FakeDC("127.0.0.1", WS_PORT, "ws")
    ws_hole = FakeDC("127.0.0.2", WS_PORT, "ws", "blackhole")
    tcp_good = FakeDC("127.0.0.1", TCP_PORT, "tcp")
    print("== тесты ядра ==")

    def t_ws():
        n0 = len(ws_good.seen)
        px = run_mode_basic("ws", [(2, TAG_ABR, True), (-2, TAG_INT, False), (4, TAG_PAD, False)], None)
        seen = ws_good.seen[n0:]
        dcs = sorted((s["dc"], s["tag"]) for s in seen)
        assert (2, TAG_ABR) in dcs and (-2, TAG_INT) in dcs and (4, TAG_PAD) in dcs, f"DC/tag not preserved: {dcs}"
        assert not ws_good.violations, ws_good.violations
    check("прямой WS (TLS+SNI): abridged/intermediate/padded, media, 3 МБ эхо", t_ws)

    def t_conc():
        px = Proxy("ws", SECRET)
        try:
            errs = []
            def w():
                try: handshake_and_echo(px.port, random.choice([2, 4]), random.choice([TAG_ABR, TAG_INT, TAG_PAD]))
                except Exception as e: errs.append(repr(e))
            ts = [threading.Thread(target=w) for _ in range(24)]
            [t.start() for t in ts]; [t.join() for t in ts]
            assert not errs, errs[:3]
            assert not ws_good.violations, ws_good.violations
        finally:
            px.stop()
    check("24 параллельных клиента", t_conc)

    def t_badsecret():
        px = Proxy("ws", SECRET)
        try:
            c = TgClient(px.port, bytes(16), 2)
            c.sock.settimeout(5)
            try:
                data = c.sock.recv(10)
                assert data == b"", f"expected close, got {data!r}"
            except ConnectionResetError:
                pass
            time.sleep(0.3)
            assert "неверный секрет" in px.log_text(), px.log_text()
        finally:
            px.stop()
    check("неверный секрет → соединение закрыто", t_badsecret)

    def t_cf():
        n0 = len(ws_good.seen)
        run_mode_basic("cf", [(2, TAG_ABR, False), (5, TAG_INT, False)], None)
        paths = [s["path"] for s in ws_good.seen[n0:]]
        assert all(p.startswith("/apiws?dst=") for p in paths), paths
        assert any("149.154.171.5" in p for p in paths), paths      # dst для DC5
    check("Cloudflare Worker (?dst=, ws:// без TLS)", t_cf)

    def t_tcp():
        n0 = len(tcp_good.seen)
        run_mode_basic("tcp", [(2, TAG_ABR, True), (3, TAG_PAD, False)], None)
        assert len(tcp_good.seen) - n0 == 2
    check("прямой TCP", t_tcp)

    def t_refuse():
        px = Proxy("refuse", SECRET)
        try:
            t = time.time()
            handshake_and_echo(px.port, 2, TAG_ABR)
            assert time.time() - t < 4, "слишком долго"
            assert "работает через «TCP" in px.log_text(), px.log_text()
        finally:
            px.stop()
    check("WS недоступен (connection refused) → переключение на TCP", t_refuse)

    def t_failover():
        px = Proxy("failover", SECRET)
        try:
            t = time.time()
            c = TgClient(px.port, SECRET, 2)
            nonce = os.urandom(16)
            c.send_payloads([req_pq_payload(nonce)])
            check_res_pq(c.recv_payload(), nonce)
            first = time.time() - t
            c.close()
            assert 2.5 < first < 8, f"первый ответ за {first:.1f}s — ожидалось ~3 с (2 таймаута по 1.5 с)"
            # маршруты-«чёрные дыры» должны быть запомнены → второй клиент идёт сразу в TCP
            t = time.time()
            c = TgClient(px.port, SECRET, 2)
            nonce = os.urandom(16)
            c.send_payloads([req_pq_payload(nonce)])
            check_res_pq(c.recv_payload(), nonce)
            second = time.time() - t
            c.close()
            assert second < 1.0, f"второй клиент ждал {second:.1f}s — маршрут не запомнился"
            print(f"        первый ответ: {first:.1f}s, второй: {second:.2f}s")
        finally:
            px.stop()
    check("WS молчит (чёрная дыра) → таймаут → повтор запроса на TCP + запоминание маршрута", t_failover)

    def t_diag():
        p = subprocess.run(["java", "-cp", f"{OUT}:{STDLIB}", "app.tgproxy.selftest.HarnessKt", "diag", "0", SECRET.hex(),
                            str(WS_PORT), str(TCP_PORT), CERT], capture_output=True, text=True, timeout=60)
        lines = [l for l in p.stdout.splitlines() if l.startswith("DIAG")]
        print("        " + "\n        ".join(lines))
        assert len(lines) == 4 and all(" OK " in l for l in lines), p.stdout
    check("диагностика: все 4 маршрута отвечают resPQ", t_diag)

    def t_diag_bad():
        p = subprocess.run(["java", "-cp", f"{OUT}:{STDLIB}", "app.tgproxy.selftest.HarnessKt", "diag-bad", "0", SECRET.hex(),
                            str(WS_PORT), str(TCP_PORT), CERT], capture_output=True, text=True, timeout=90)
        lines = [l for l in p.stdout.splitlines() if l.startswith("DIAG")]
        print("        " + "\n        ".join(lines))
        assert len(lines) == 3 and all("FAIL" in l for l in lines), p.stdout
        assert any("таймаут" in l for l in lines)
    check("диагностика: нерабочие маршруты честно помечаются FAIL", t_diag_bad)

    print()
    bad = [r for r in results if not r[1]]
    print(f"итого: {len(results) - len(bad)}/{len(results)} OK")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
