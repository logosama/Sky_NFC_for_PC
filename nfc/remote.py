"""remote - Remote NFC backend: receives badge dumps from the Android app

The phone reads raw NTAG215 memory (the same 540-byte dump as local readers),
base64-encodes it and POSTs to this HTTP listener. Same contract as the other
backends: read_once() -> (uid, ndef_bytes) or None.

Only used when explicitly selected (config nfc.backend == "remote" or the
--remote flag); auto mode never picks it.
"""
import base64
import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from runtime import load_config

_state_lock = threading.Lock()
_server = None
_queue = queue.Queue(maxsize=8)


def _ensure_server():
    """Start the shared HTTP listener once (thread-safe)."""
    global _server
    with _state_lock:
        if _server is not None:
            return
        cfg = load_config()
        port = int(cfg.get("remote", {}).get("port", 8799))
        token = cfg.get("remote", {}).get("token", "")

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                if self.path.rstrip("/") != "/inject":
                    self.send_response(404)
                    self.end_headers()
                    return
                if token and self.headers.get("X-Auth-Token", "") != token:
                    self.send_response(403)
                    self.end_headers()
                    return
                try:
                    length = int(self.headers.get("Content-Length", 0))
                    payload = json.loads(self.rfile.read(length))
                    data = base64.b64decode(payload["data_base64"])
                    if len(data) < 540:
                        raise ValueError("badge dump too short")
                except Exception:
                    self.send_response(400)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"accepted"}')
                try:
                    _queue.put_nowait(bytes(data))
                except queue.Full:
                    pass

            def log_message(self, *args):  # keep console quiet
                pass

        try:
            _server = ThreadingHTTPServer(("0.0.0.0", port), Handler)
        except OSError:
            _server = None
            return
        threading.Thread(target=_server.serve_forever, daemon=True).start()


class RemoteBackend:
    name = "remote"

    def available(self):
        # Explicitly selected by the user, not subject to device detection
        return True

    def read_once(self):
        """Wait up to 2s for one phone POST; returns (uid, ndef_bytes) or None"""
        _ensure_server()
        try:
            data = _queue.get(timeout=2.0)
        except queue.Empty:
            return None
        uid = " ".join(f"{b:02x}" for b in (data[0:3] + data[4:8]))
        return uid, bytes(data)


def ensure_server_started():
    """Start the listener immediately (e.g. at tool startup in --remote mode),
    so phone scans made before the scan window opens are queued."""
    _ensure_server()
    return _server is not None
