"""nfc - NFC badge reading backend abstraction
Unified interface: read_badge(timeout) -> (uid, ndef_bytes) or None
Backend selection: config.json nfc.backend (auto|libnfc|pcsc)
"""
import sys
import time

from runtime import badge_dump_path, load_config


def get_backend(name=None):
    """Get NFC backend by name or auto-detect"""
    cfg = load_config()
    backend = name or cfg.get("nfc", {}).get("backend", "auto")

    from nfc import libnfc_cli, pcsc_ctypes  # noqa: E402

    if backend == "remote":
        from nfc import remote
        return remote.RemoteBackend()

    backends = []
    if backend in ("auto", "libnfc"):
        if sys.platform == "win32":
            if backend == "libnfc":
                raise RuntimeError(
                    "libnfc backend is not available on Windows; use 'pcsc' or 'remote'")
        else:
            backends.append(libnfc_cli.LibnfcBackend())
    if backend in ("auto", "pcsc"):
        backends.append(pcsc_ctypes.PcscBackend())

    for b in backends:
        if b.available():
            return b
    return None


def read_badge(timeout=35, backend=None):
    """Read badge, returns (uid, ndef_bytes). Polls until timeout or success."""
    cfg = load_config()
    interval = cfg.get("nfc", {}).get("poll_interval", 0.5)

    b = get_backend(backend)
    if not b:
        raise RuntimeError(
            "No NFC backend available (check the PC/SC reader, "
            "libnfc on Linux, or use --remote with the phone relay)")

    deadline = time.time() + timeout
    while time.time() < deadline:
        result = b.read_once()
        if result:
            return result
        time.sleep(interval)
    return None
