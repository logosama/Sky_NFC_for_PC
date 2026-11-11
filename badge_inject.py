#!/usr/bin/env python3
"""Sky badge injection tool (cross-platform)

Always-listening mode: choose an external NFC reader or the phone remote relay
once, then every badge scan is parsed and injected automatically. Injection
still goes through the in-game hook, which executes it on the game thread.

Dependencies:
- Linux:  libnfc (PN532/ACR122) or pcsclite (PC/SC readers)
- Windows: winscard.dll (built-in) or inject_dll.py + sky_hook.dll
"""
import argparse
import os
import signal
import socket
import sys
import time

from runtime import app_dir, find_runtime_file, load_config

DEFAULT_IPC_TIMEOUT = 5.0
HOOK_RETRY_TIMEOUT = 30.0
HOOK_WAIT_POLL = 2.0


def log(message=""):
    """Print and flush: important when stdout is redirected in the background."""
    print(message, flush=True)


# ============ Hook IPC ============

class HookClient:
    """Small TCP client for the hook, with a cached port and stale-port recovery."""

    def __init__(self):
        self.port = None

    def _read_port(self):
        port_file = find_runtime_file("ipc_port")
        if not port_file:
            return None
        try:
            with open(port_file) as f:
                return int(f.read().strip())
        except (OSError, ValueError):
            return None

    def command(self, cmd, timeout=DEFAULT_IPC_TIMEOUT, quiet=False):
        """Send one command; retry once after rereading the port file."""
        last_error = None
        for _ in (1, 2):
            port = self.port or self._read_port()
            if port is None:
                if not quiet:
                    log("  x hook not running (port file missing)")
                return None
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
                s.sendall(cmd.encode() + b"\n")
                resp = s.recv(8192).decode(errors="replace").strip()
                s.close()
                if not resp:
                    self.port = None
                return resp or None
            except OSError as e:
                last_error = e
                self.port = None
        if not quiet:
            log(f"  x IPC error: {last_error}")
        return None

    def ping(self, quiet=False):
        return self.command("ping", timeout=2.0, quiet=quiet)


def wait_for_hook(hook, timeout=None, announce=False):
    """Wait until the game's main hook process answers; None on timeout.

    timeout=None waits forever (startup/continuous mode). A finite timeout is
    used when a scan is already waiting and the game restarted mid-injection.
    """
    start = time.monotonic()
    next_status = start + 30.0
    warned = False
    while True:
        ping = hook.ping(quiet=True)
        if ping and "main=1" in ping:
            if warned or announce:
                log(f"OK hook connected ({ping})")
            return ping

        now = time.monotonic()
        if not warned:
            log("WARN hook not connected; waiting for the game hook...")
            if sys.platform == "win32":
                log("  Windows: run SkyBadgeInjector.exe "
                    "(as Administrator if Sky.exe is elevated)")
            else:
                log(f"  Linux launch options: LD_PRELOAD="
                    f"{os.path.join(app_dir(), 'sky_hook.so')} %command%")
            warned = True
        elif now >= next_status:
            log(f"  [hook] still waiting ({now - start:.0f}s)")
            next_status = now + 30.0

        if timeout is not None and now - start >= timeout:
            return None
        time.sleep(HOOK_WAIT_POLL)


# ============ NDEF parsing ============

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


# ============ NFC source selection ============

def reader_backend_name(cfg):
    """Config backend for reader mode; never let config 'remote' hijack it."""
    backend = cfg.get("nfc", {}).get("backend", "auto")
    return "auto" if backend == "remote" else backend


def pick_reader(cfg):
    """Detect an external reader and return its backend name, or None."""
    from nfc import get_backend
    name = reader_backend_name(cfg)
    log(f"  [nfc] detecting external reader ({name})...")
    try:
        backend = get_backend(name)
    except Exception as e:
        log(f"  x reader detection failed: {e}")
        return None
    if not backend:
        log("  x no external NFC reader found (libnfc/PC-SC)")
        return None
    log(f"  [nfc] backend: {backend.name}")
    return backend.name


def choose_mode(args, cfg):
    """Return (mode, backend_name); menu only when no flag and a TTY is present."""
    if args.remote:
        return "remote", "remote"
    if args.reader:
        name = pick_reader(cfg)
        if not name:
            raise SystemExit(1)
        return "reader", name

    if not sys.stdin.isatty():
        log("No mode selected and stdin is not a TTY. Pass --reader or --remote.")
        raise SystemExit(2)

    while True:
        log("Select NFC source:")
        log("  1) External NFC reader (auto-detect libnfc / PC-SC)")
        log("  2) Phone remote (HTTP listener)")
        log("  q) Quit")
        try:
            choice = input("Choice [1/2]: ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            log("\nGoodbye!")
            raise SystemExit(0)
        if choice in ("1", "r", "reader"):
            name = pick_reader(cfg)
            if name:
                return "reader", name
        elif choice in ("2", "p", "remote"):
            return "remote", "remote"
        elif choice in ("q", "quit", "exit"):
            log("Goodbye!")
            raise SystemExit(0)
        else:
            log("  invalid choice")


def start_remote(cfg):
    """Start the HTTP listener; return False if the port cannot be bound."""
    from nfc import remote
    port = cfg.get("remote", {}).get("port", 8799)
    if not remote.ensure_server_started():
        log(f"  x cannot start remote listener on 0.0.0.0:{port} (port in use?)")
        return False
    log(f"OK remote listener on 0.0.0.0:{port} (phone scans auto-inject)")
    token = str(cfg.get("remote", {}).get("token", "") or "")
    if not token:
        log("WARN remote.token is empty: any device that can reach this PC on the LAN")
        log("     can inject scans. Set remote.token in config.json and enter it in the app.")
    return True


# ============ Scanning and injection ============

def scan_badge(cfg, backend_name, timeout=None):
    """One finite scan (used by --once); returns (uid, data) or None."""
    from nfc import read_badge
    if timeout is None:
        timeout = cfg.get("nfc", {}).get("scan_timeout", 35)
    if backend_name == "remote":
        log(f"  [scan] Waiting for phone scan... ({timeout}s window)")
    else:
        log(f"  [scan] Place badge on reader... ({timeout}s window, keep it there)")
    try:
        return read_badge(timeout=timeout, backend=backend_name)
    except RuntimeError as e:
        log(f"  x {e}")
        return None


def wait_for_badge(cfg, backend_name):
    """Block until a badge arrives; retry absent/busy readers without exiting."""
    from nfc import read_badge
    while True:
        try:
            return read_badge(timeout=None, backend=backend_name)
        except RuntimeError as e:
            log(f"  x {e}; retrying in 2s...")
            time.sleep(2)
        except OSError as e:
            log(f"  x NFC error: {e}; retrying in 2s...")
            time.sleep(2)


def inject_url(url, cfg, hook):
    """Install the hook if needed, queue the URL, and confirm INJECT done."""
    retry_timeout = float(cfg.get("game", {}).get("hook_retry_timeout", HOOK_RETRY_TIMEOUT))
    ping = wait_for_hook(hook, timeout=retry_timeout)
    if not ping:
        log("  x hook not available; scan dropped")
        return False
    log(f"  [status] {ping}")
    if "hook=0" in ping:
        log("  [inject] installing hook...")
        resp = hook.command("hook")
        log(f"  [inject] {resp}")
        if resp != "hook OK":
            return False

    # Queue the URL. A previous injection can still be pending, so retry busy.
    queue_deadline = time.monotonic() + 5.0
    while True:
        resp = hook.command(f"inject {url}")
        log(f"  [inject] {resp}")
        if resp == "queued":
            break
        if resp == "busy" and time.monotonic() < queue_deadline:
            time.sleep(0.5)
            continue
        if resp is None:
            log("  x hook disconnected during inject; waiting...")
            if not wait_for_hook(hook, timeout=retry_timeout):
                return False
            if time.monotonic() < queue_deadline:
                continue
        return False

    # The game executes the URL on its next analytics tick; poll the log.
    log_file = find_runtime_file("hook.log")
    if not log_file:
        log("  x hook.log not found")
        return False
    inject_timeout = float(cfg.get("nfc", {}).get("inject_timeout", 10.0))
    deadline = time.monotonic() + inject_timeout
    anchor = f"CMD:inject {url}"
    while True:
        try:
            with open(log_file, errors="replace") as f:
                lines = f.read().splitlines()
        except OSError:
            lines = []
        start = next((i for i in range(len(lines) - 1, -1, -1) if anchor in lines[i]), None)
        if start is not None:
            end = next((j for j in range(start + 1, len(lines)) if "CMD:inject " in lines[j]),
                       len(lines))
            hits = [l for l in lines[start + 1:end] if "INJECT" in l]
            if any("INJECT done" in l for l in hits):
                log("  [result] OK injection executed!")
                for line in hits:
                    log(f"  [log] {line}")
                return True
        if time.monotonic() >= deadline:
            break
        time.sleep(0.5)

    log("  [result] injection not executed (still queued?)")
    log(f"  [log] {log_file}")
    return False


def handle_badge(result, cfg, hook):
    """Parse one (uid, data) result and inject it; returns True on INJECT done."""
    uid, data = result
    log(f"  OK badge UID: {uid}")
    url = parse_ndef(data)
    if not url:
        log("  x NDEF parse failed")
        return False
    log(f"  OK NDEF URL: {url[:70]}...")
    return inject_url(url, cfg, hook)


def run_loop(mode, backend_name, cfg, hook):
    cooldown = float(cfg.get("nfc", {}).get("cooldown", 3.0))
    last_url = None
    last_time = 0.0
    log("Waiting for badge... (Ctrl+C to quit)")
    while True:
        result = wait_for_badge(cfg, backend_name)
        if not result:
            continue
        uid, data = result
        url = parse_ndef(data)
        if not url:
            log("  x NDEF parse failed")
            continue
        now = time.monotonic()
        if url == last_url and now - last_time < cooldown:
            log("  [skip] duplicate scan within cooldown")
            continue
        log(f"  [{time.strftime('%H:%M:%S')}] OK badge UID: {uid}")
        log(f"  OK NDEF URL: {url[:70]}...")
        last_url, last_time = url, now
        if inject_url(url, cfg, hook):
            last_time = time.monotonic()
        time.sleep(cooldown)
        log("Waiting for next badge... (Ctrl+C to quit)")


def run_once(mode, backend_name, cfg, hook):
    ping = wait_for_hook(hook, timeout=5.0, announce=True)
    if not ping:
        log("  x hook not connected; cannot inject")
        return 1
    result = scan_badge(cfg, backend_name)
    if not result:
        return 1
    return 0 if handle_badge(result, cfg, hook) else 1


# ============ Misc ============

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


def _sigterm(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except (AttributeError, OSError):
        pass
    try:
        signal.signal(signal.SIGTERM, _sigterm)
    except (AttributeError, ValueError, OSError):
        pass  # Windows may not deliver SIGTERM; Ctrl+C still works

    parser = argparse.ArgumentParser(
        description="Sky badge injection tool: choose a reader, then auto-inject every scan.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--remote", action="store_true",
                       help="phone relay over HTTP (listener starts immediately)")
    group.add_argument("--reader", action="store_true",
                       help="external NFC reader (auto-detect libnfc / PC-SC)")
    parser.add_argument("--once", action="store_true",
                        help="scan one badge within nfc.scan_timeout and exit")
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.self_test:
        # Exercise the dynamically imported backends for frozen-build CI.
        from nfc import libnfc_cli, pcsc_ctypes, remote  # noqa: F401
        log("OK self-test")
        return 0

    log("=" * 60)
    log("  Sky Badge Injection Tool")
    log("=" * 60)
    cfg = load_config()
    hook = HookClient()
    try:
        mode, backend_name = choose_mode(args, cfg)
        log(f"Mode: {mode} ({backend_name})")

        if mode == "remote" and not start_remote(cfg):
            return 1
        if args.once:
            return run_once(mode, backend_name, cfg, hook)
        wait_for_hook(hook, announce=True)
        return run_loop(mode, backend_name, cfg, hook)
    except KeyboardInterrupt:
        log("\nGoodbye!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
