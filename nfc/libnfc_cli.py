"""libnfc CLI backend - reads badges via nfc-mfultralight CLI tool
Supports all libnfc device drivers (pn532_uart, acr122_usb, acr122_pcsc, etc.)
"""
import os
import subprocess

from nfc import badge_dump_path


class LibnfcBackend:
    name = "libnfc"

    def available(self):
        """Check if libnfc CLI tools are available"""
        try:
            r = subprocess.run(["nfc-list"], capture_output=True, text=True, timeout=3)
            return "NFC device" in (r.stdout + r.stderr)
        except Exception:
            return False

    def read_once(self):
        """Attempt one badge read, returns (uid, ndef_bytes) or None"""
        dump = badge_dump_path()
        os.makedirs(os.path.dirname(dump), exist_ok=True)
        # Remove old dump to prevent reusing stale data (counter anti-replay)
        if os.path.exists(dump):
            os.remove(dump)

        try:
            r = subprocess.run(
                ["nfc-mfultralight", "r", dump],
                capture_output=True, text=True, timeout=5,
            )
        except subprocess.TimeoutExpired:
            return None

        out = r.stdout + r.stderr
        if "already claimed" in out or "Unable to open" in out:
            raise RuntimeError("NFC device busy (replug reader and retry)")

        if "ERROR" in out:
            return None
        if not (os.path.exists(dump) and os.path.getsize(dump) >= 540):
            return None

        with open(dump, "rb") as f:
            data = f.read()
        uid = " ".join(f"{b:02x}" for b in (data[0:3] + data[4:8]))
        return uid, data
