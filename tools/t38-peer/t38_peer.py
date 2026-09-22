#!/usr/bin/env python3
"""A T.38 terminal peer built on the system libspandsp via ctypes.

Usage:
  t38_peer.py make-page OUT.tif WIDTH HEIGHT [PAGES]
  t38_peer.py callee --listen IP:PORT --out OUT.tif [--timeout S] [--verbose]
  t38_peer.py caller --remote IP:PORT --send IN.tif [--timeout S] [--verbose]

Exit code 0 iff the T.30 session completed (phase E reported OK).
The callee prints `PAGEHASH <width> <height> <sha256>` after receiving a page.
"""

import argparse
import ctypes as C
import ctypes.util
import hashlib
import os
import select
import socket
import sys
import time

TICK_MS = 30
TICK_SAMPLES = 8 * TICK_MS
SPAN_LOG_FLOW = 5

TX_HANDLER = C.CFUNCTYPE(C.c_int, C.c_void_p, C.c_void_p, C.POINTER(C.c_ubyte), C.c_int, C.c_int)
PHASE_E_HANDLER = C.CFUNCTYPE(None, C.c_void_p, C.c_void_p, C.c_int)

_state = {
    "sock": None,
    "far": None,
    "tx_seq": 0,
    "finished": False,
    "completion": -1,
    "t38_core": None,
}


def load_spandsp():
    candidates = []
    found = ctypes.util.find_library("spandsp")
    if found:
        candidates.append(found)
    for prefix in ("/opt/homebrew/opt/spandsp/lib", "/usr/local/lib", "/usr/lib"):
        candidates.append(os.path.join(prefix, "libspandsp.dylib"))
        candidates.append(os.path.join(prefix, "libspandsp.so"))
    for path in candidates:
        if path and os.path.exists(path):
            return C.CDLL(path)
    raise OSError("libspandsp not found")


LIB = load_spandsp()


def bind_fn(name, restype, argtypes):
    fn = getattr(LIB, name)
    fn.restype = restype
    fn.argtypes = argtypes
    return fn


def bind_api():
    vp, i = C.c_void_p, C.c_int
    bind_fn("t38_terminal_init", vp, [vp, i, TX_HANDLER, vp])
    bind_fn("t38_terminal_get_t30_state", vp, [vp])
    bind_fn("t38_terminal_get_t38_core_state", vp, [vp])
    bind_fn("t38_terminal_get_logging_state", vp, [vp])
    bind_fn("t38_terminal_send_timeout", i, [vp, i])
    bind_fn("t38_terminal_restart", i, [vp, i])
    bind_fn("t38_terminal_release", i, [vp])
    bind_fn("t38_terminal_free", i, [vp])
    bind_fn("t38_set_t38_version", None, [vp, i])
    bind_fn("t38_core_rx_ifp_packet", i, [vp, C.POINTER(C.c_ubyte), i, C.c_uint16])
    bind_fn("t30_set_supported_modems", i, [vp, i])
    bind_fn("t30_set_tx_ident", i, [vp, C.c_char_p])
    bind_fn("t30_set_tx_file", None, [vp, C.c_char_p, i, i])
    bind_fn("t30_set_rx_file", None, [vp, C.c_char_p, i])
    bind_fn("t30_set_phase_e_handler", None, [vp, PHASE_E_HANDLER, vp])
    bind_fn("span_log_set_level", None, [vp, i])
    bind_fn("t30_get_logging_state", vp, [vp])


@TX_HANDLER
def _tx_packet_handler(_core, _user, buf, length, _count):
    sock = _state["sock"]
    if sock is None or _state["far"] is None:
        return 0
    payload = bytes(buf[:length])
    print(f"PEER TX ifp {payload.hex()}", flush=True)
    pkt = _state["tx_seq"].to_bytes(2, "big") + bytes([len(payload)]) + payload + b"\x00\x00"
    try:
        sock.sendto(pkt, _state["far"])
    except OSError:
        return -1
    _state["tx_seq"] = (_state["tx_seq"] + 1) & 0xFFFF
    return 0


@PHASE_E_HANDLER
def _phase_e_handler(_t30, _user, completion_code):
    _state["completion"] = completion_code
    _state["finished"] = True


def udptl_rx(sock, on_ifp):
    data, _ = sock.recvfrom(4096)
    if len(data) < 3:
        return
    seq = int.from_bytes(data[0:2], "big")
    plen = data[2]
    if 3 + plen > len(data):
        return
    on_ifp(data[3 : 3 + plen], seq)


def feed_ifp(ifp, seq):
    print(f"PEER RX ifp seq={seq} {ifp.hex()}", flush=True)
    core = _state["t38_core"]
    arr = (C.c_ubyte * len(ifp)).from_buffer_copy(ifp)
    LIB.t38_core_rx_ifp_packet(core, arr, len(ifp), seq)


def run_peer(caller, remote_spec, listen_spec, tiff, timeout, verbose=False):
    bind_api()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    far = None
    if caller:
        host, port = remote_spec.split(":")
        far = (host, int(port))
        bind_to = ("127.0.0.1", int(listen_spec.split(":")[1])) if listen_spec else ("127.0.0.1", 0)
        sock.bind(bind_to)
    else:
        host, port = listen_spec.split(":")
        sock.bind((host, int(port)))
    sock.setblocking(False)

    t38 = LIB.t38_terminal_init(None, 1 if caller else 0, _tx_packet_handler, None)
    if not t38:
        print("PEER init failed", file=sys.stderr)
        return 2
    t30 = LIB.t38_terminal_get_t30_state(t38)
    core = LIB.t38_terminal_get_t38_core_state(t38)
    _state["sock"] = sock
    _state["far"] = far
    _state["t38_core"] = core

    LIB.t38_set_t38_version(core, 3)
    LIB.t30_set_supported_modems(t30, 0x01)
    LIB.t30_set_tx_ident(t30, b"rustrtc-interop")
    if caller:
        LIB.t30_set_tx_file(t30, tiff.encode(), -1, -1)
    else:
        LIB.t30_set_rx_file(t30, tiff.encode(), -1)
    LIB.t30_set_phase_e_handler(t30, _phase_e_handler, None)
    if verbose:
        LIB.span_log_set_level(LIB.t38_terminal_get_logging_state(t38), SPAN_LOG_FLOW)
        LIB.span_log_set_level(LIB.t30_get_logging_state(t30), SPAN_LOG_FLOW)

    print(f"PEER ready role={'caller' if caller else 'callee'} local={sock.getsockname()} far={_state['far']}")
    sys.stdout.flush()

    start = time.monotonic()
    last_tick = start
    pending = 0
    latched = caller
    while not _state["finished"]:
        r, _, _ = select.select([sock], [], [], 0.005)
        if r:
            data, addr = sock.recvfrom(4096)
            if not latched:
                _state["far"] = addr
                latched = True
                print(f"PEER latched far end {addr}", flush=True)
            if len(data) >= 3:
                seq = int.from_bytes(data[0:2], "big")
                plen = data[2]
                if 3 + plen <= len(data):
                    feed_ifp(data[3 : 3 + plen], seq)
        if not latched:
            if time.monotonic() - start > timeout:
                print(f"PEER timeout waiting for far end after {timeout}s")
                break
            continue
        now = time.monotonic()
        if (now - last_tick) * 1000 >= TICK_MS:
            last_tick = now
            pending += TICK_SAMPLES
            while pending >= 240:
                LIB.t38_terminal_send_timeout(t38, 240)
                pending -= 240
        if now - start > timeout:
            print(f"PEER timeout after {timeout}s")
            break

    code = _state["completion"]
    LIB.t38_terminal_release(t38)
    LIB.t38_terminal_free(t38)
    sock.close()
    ok = _state["finished"] and code == 0
    if ok and not caller:
        try:
            page_hash(tiff)
        except Exception as e:
            print(f"PEER page hash failed: {e}")
    print(f"PEER done code={code}")
    return 0 if ok else 1


def page_hash(path):
    from PIL import Image

    img = Image.open(path)
    if img.mode != "1":
        img = img.convert("1")
    w, h = img.size
    px = img.load()
    digest = hashlib.sha256()
    for y in range(h):
        row = bytearray(w // 8)
        for i in range(w // 8):
            byte = 0
            for k in range(8):
                if px[i * 8 + k, y] == 0:
                    byte |= 0x80 >> k
            row[i] = byte
        digest.update(bytes(row))
    print(f"PAGEHASH {w} {h} {digest.hexdigest()}")


def make_page(out, width, height, pages):
    from PIL import Image

    imgs = []
    for page in range(pages):
        img = Image.new("1", (width, height), 1)
        px = img.load()
        for y in range(height):
            rr = y + page * height
            for i in range(width // 8):
                col = i * 8
                black = (
                    rr >= 4
                    and ((rr // 4 + col // 48) % 2 == 0)
                    and (rr % 4 < 2 or col % 64 < 32)
                )
                if black:
                    for k in range(8):
                        px[col + k, y] = 0
        imgs.append(img)
    imgs[0].save(out, compression="group3", dpi=(204, 98), save_all=len(imgs) > 1, append_images=imgs[1:])
    print(f"PEER made {out} {width}x{height} pages={len(imgs)}")
    return 0


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)

    mk = sub.add_parser("make-page")
    mk.add_argument("out")
    mk.add_argument("width", type=int)
    mk.add_argument("height", type=int)
    mk.add_argument("pages", type=int, nargs="?", default=1)

    for name, mode in (("callee", 0), ("caller", 1)):
        sp = sub.add_parser(name)
        sp.add_argument("--listen")
        sp.add_argument("--local")
        sp.add_argument("--remote")
        sp.add_argument("--out" if mode == 0 else "--send", dest="tiff", required=True)
        sp.add_argument("--timeout", type=int, default=90)
        sp.add_argument("--verbose", action="store_true")

    args = ap.parse_args()
    if args.cmd == "make-page":
        sys.exit(make_page(args.out, args.width, args.height, args.pages))

    bind_api()
    sys.exit(
        run_peer(
            args.cmd == "caller",
            args.remote,
            args.local if args.cmd == "caller" else args.listen,
            args.tiff,
            args.timeout,
            getattr(args, "verbose", False),
        )
    )


if __name__ == "__main__":
    main()
