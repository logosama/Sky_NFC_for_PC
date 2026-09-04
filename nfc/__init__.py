"""nfc - NFC badge reading backend abstraction
Unified interface: read_badge(timeout) -> (uid, ndef_bytes) or None
Backend selection: config.json nfc.backend (auto|libnfc|pcsc)
"""
import os
import sys
import time
import json

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_config():
    cfg_path = os.path.join(PROJECT_ROOT, "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _work_dir():
    cfg = _load_config()
    wd = cfg.get("paths", {}).get("work_dir", "data")
    return os.path.join(PROJECT_ROOT, wd)


def get_backend(name=None):
    """Get NFC backend by name or auto-detect"""
    cfg = _load_config()
    backend = name or cfg.get("nfc", {}).get("backend", "auto")

    from nfc import libnfc_cli, pcsc_ctypes  # noqa: E402

    backends = []
    if backend in ("auto", "libnfc"):
        backends.append(libnfc_cli.LibnfcBackend())
    if backend in ("auto", "pcsc"):
        backends.append(pcsc_ctypes.PcscBackend())

    for b in backends:
        if b.available():
            return b
    return None


def read_badge(timeout=35, backend=None):
    """Read badge, returns (uid, ndef_bytes). Polls until timeout or success."""
    b = get_backend(backend)
    if not b:
        raise RuntimeError("No NFC backend available (check libnfc or PC/SC reader)")

    deadline = time.time() + timeout
    while time.time() < deadline:
        result = b.read_once()
        if result:
            return result
        time.sleep(0.5)
    return None


def badge_dump_path():
    cfg = _load_config()
    name = cfg.get("paths", {}).get("badge_dump", "badge.mfd")
    return os.path.join(_work_dir(), name)
