#!/usr/bin/env python3
"""Sky badge injection tool (cross-platform)
Scan NFC badge -> parse NDEF URL -> inject into game (game thread handles it with its own function)

Dependencies:
- Linux:  libnfc (PN532/ACR122) or pcsclite (PC/SC readers)
- Windows: winscard.dll (built-in) or injector + sky_hook.dll
"""
import json
import os
import socket
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def load_config():
    with open(os.path.join(PROJECT_ROOT, "config.json"), encoding="utf-8") as f:
        return json.load(f)


def runtime_dirs():
    """Runtime directories to probe, in priority order.
    Mirrors the hook side: SKY_BADGE_DIR is preferred, but under Proton the
    LD_PRELOAD dir is bind-mounted read-only inside the sandbox, so the hook
    falls back to the user config dir. Probe both."""
    dirs = []
    env = os.environ.get("SKY_BADGE_DIR")
    if env:
        dirs.append(env)
    if sys.platform == "win32":
        dirs.append(os.path.join(os.environ.get("APPDATA", "."), "sky-badge"))
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            dirs.append(os.path.join(xdg, "sky-badge"))
        dirs.append(os.path.join(os.path.expanduser("~"), ".config", "sky-badge"))
    seen = []
    for d in dirs:
        if d not in seen:
            seen.append(d)
    return seen


def find_runtime_file(name):
    """Return path of runtime file if present in any runtime dir"""
    for d in runtime_dirs():
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None


def ipc_port():
    """Read the random port hook is listening on"""
    for _ in range(50):  # wait up to 5 seconds
        port_file = find_runtime_file("ipc_port")
        if port_file:
            try:
                with open(port_file) as f:
                    return int(f.read().strip())
            except ValueError:
                pass
        time.sleep(0.1)
    return None


def ipc_cmd(cmd, timeout=30):
    """Send command to hook over TCP"""
    port = ipc_port()
    if not port:
        print("  x hook not running (port file missing)")
        return None
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.sendall(cmd.encode() + b"\n")
        resp = s.recv(8192).decode(errors="replace").strip()
        s.close()
        return resp
    except OSError as e:
        print(f"  x IPC error: {e}")
        return None


def parse_ndef(data):
    """Parse NTAG215 NDEF TLV, extract URI (from page 4)"""
    i = 0x10
    while i < len(data) - 4:
        tag = data[i]
        if tag == 0x00:
            i += 1
            continue
        if tag == 0xFE:
            break
        if tag == 0x03:  # NDEF TLV
            if data[i + 1] == 0xFF:
                length = (data[i + 2] << 8) | data[i + 3]
                start = i + 4
            else:
                length = data[i + 1]
                start = i + 2
            return parse_uri_record(data[start:start + length])
        i += 2 + data[i + 1]
    return None


def parse_uri_record(ndef):
    """Parse NDEF URI record (TNF=1, type='U')"""
    if len(ndef) < 5:
        return None
    tnf = ndef[0] & 0x07
    type_len = ndef[1]
    short = bool(ndef[0] & 0x10)
    payload_len = ndef[2] if short else int.from_bytes(ndef[2:6], "big")
    idx = 3 if short else 6
    rec_type = ndef[idx:idx + type_len]
    payload = ndef[idx + type_len:idx + type_len + payload_len]
    if tnf == 1 and rec_type == b"U":
        prefixes = {0x00: "", 0x01: "http://www.", 0x02: "https://www.",
                    0x03: "http://", 0x04: "https://"}
        return prefixes.get(payload[0], "") + payload[1:].decode("utf-8", errors="replace")
    return None


def scan_badge(cfg):
    """Poll badge read through NFC backend"""
    from nfc import read_badge
    timeout = cfg.get("nfc", {}).get("scan_timeout", 35)
    print(f"  [scan] Place badge on reader... ({timeout}s window, keep it there)")
    try:
        result = read_badge(timeout=timeout)
    except RuntimeError as e:
        print(f"  x {e}")
        return None
    if not result:
        print("  x badge not detected")
        return None
    return result


def inject_url(url, cfg):
    """Inject via IPC: ensure hook installed -> queue URL -> executed on game thread"""
    ping = ipc_cmd("ping") or ""
    print(f"  [status] {ping}")
    if "hook=0" in ping:
        print("  [inject] installing hook...")
        print(f"  [inject] {ipc_cmd('hook')}")

    print("  [inject] queueing URL (game thread will execute)...")
    print(f"  [inject] {ipc_cmd(f'inject {url}')}")

    time.sleep(3)  # wait for game thread to trigger
    log_file = find_runtime_file("hook.log")
    if log_file:
        with open(log_file) as f:
            log = f.read()
        if "INJECT done" in log:
            print("  [result] OK injection executed!")
            for line in log.splitlines():
                if "INJECT" in line:
                    print(f"  [log] {line}")
        else:
            print("  [result] injection not executed")
            print(f"  [log] {log_file}")


def game_log_path():
    """Auto-locate game log per platform (overridable via config)"""
    cfg = load_config()
    p = cfg.get("game", {}).get("log_path")
    if p and p != "auto":
        return p
    if sys.platform == "win32":
        # Windows Steam default paths (registry lookup ideal; fall back to common locations)
        for base in (os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)"),
                     r"C:\Program Files (x86)", r"D:\SteamLibrary", r"E:\SteamLibrary"):
            p = os.path.join(base, "Steam", "steamapps", "common",
                             "Sky Children of the Light", "Sky.log")
            if os.path.exists(p):
                return p
        return None
    # Linux Steam standard paths
    for p in (
        os.path.expanduser("~/.steam/steam/steamapps/common/Sky Children of the Light/Sky.log"),
        os.path.expanduser("~/.local/share/Steam/steamapps/common/Sky Children of the Light/Sky.log"),
    ):
        if os.path.exists(p):
            return p
    return None


def main():
    print("=" * 60)
    print("  Sky Badge Injection Tool")
    print("=" * 60)
    cfg = load_config()

    ping = ipc_cmd("ping")
    if ping and "main=1" in ping:
        print(f"OK hook connected ({ping})")
    else:
        print("WARN hook not connected. For Linux configure Steam launch options:")
        print(f"  LD_PRELOAD={os.path.join(PROJECT_ROOT, 'sky_hook.so')} %command%")
        if sys.platform == "win32":
            print("  For Windows run: python3 injector.py")
    print()
    print("Commands:  s/scan scan badge and inject | h help | q quit")
    print()

    while True:
        try:
            cmd = input("sky> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\nGoodbye!")
            break

        if cmd in ("q", "quit", "exit"):
            print("Goodbye!")
            break
        elif cmd in ("h", "help", ""):
            print("  s/scan  scan badge and inject")
            print("  q/quit  quit")
        elif cmd in ("s", "scan"):
            result = scan_badge(cfg)
            if not result:
                continue
            uid, data = result
            print(f"  OK badge UID: {uid}")

            url = parse_ndef(data)
            if not url:
                print("  x NDEF parse failed")
                continue
            print(f"  OK NDEF URL: {url[:70]}...")

            inject_url(url, cfg)
        else:
            print(f"  unknown command: {cmd}")


if __name__ == "__main__":
    main()
