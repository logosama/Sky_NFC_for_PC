"""libnfc CLI backend - reads badges via nfc-mfultralight CLI tool
Supports all libnfc device drivers (pn532_uart, acr122_usb, acr122_pcsc, etc.)
Linux only: the libnfc CLI tools are not available on Windows.
"""
import glob
import os
import subprocess
import sys

from nfc import badge_dump_path


def clear_stuck_claim():
    """libnfc marks a serial port as claimed via the CCLAIMED bit (0x80000000)
    in termios c_iflag. A killed or crashed nfc tool leaves the bit set, which
    makes every later open fail with 'Serial port already claimed' until the
    adapter is replugged. Clear the stale bit on all serial devices."""
    if sys.platform != "linux":
        return False
    cleared = False
    for dev in glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"):
        try:
            import termios
            fd = os.open(dev, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                attrs = termios.tcgetattr(fd)
                if attrs[0] & 0x80000000:
                    attrs[0] &= ~0x80000000
                    termios.tcsetattr(fd, termios.TCSANOW, attrs)
                    cleared = True
            finally:
                os.close(fd)
        except (OSError, termios.error):
            continue
    return cleared


def _run_cli(args, timeout=5):
    """Run a libnfc CLI tool; kill it on timeout (a lingering reader keeps
    the port claimed) and clear any stale claim bit. Missing tools (Windows,
    or a Linux install without libnfc) are reported as empty output so the
    auto-detection can fall through to the next backend."""
    if sys.platform == "win32":
        return ""
    try:
        proc = subprocess.Popen(
            args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    except OSError:
        return ""
    try:
        out, err = proc.communicate(timeout=timeout)
        return out + err
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        clear_stuck_claim()
        return ""
    except BaseException:
        # Ctrl+C/SIGTERM must not leave an orphaned CLI holding the reader.
        proc.kill()
        proc.communicate()
        raise


class LibnfcBackend:
    name = "libnfc"

    def available(self):
        """Check if libnfc CLI tools are available"""
        if sys.platform == "win32":
            return False
        out = _run_cli(["nfc-list"], timeout=8)
        if "claimed" in out:
            clear_stuck_claim()
            out = _run_cli(["nfc-list"], timeout=8)
        return "NFC device" in out

    def read_once(self):
        """Attempt one badge read, returns (uid, ndef_bytes) or None"""
        dump = badge_dump_path()
        os.makedirs(os.path.dirname(dump), exist_ok=True)
        # Remove old dump to prevent reusing stale data (counter anti-replay)
        if os.path.exists(dump):
            os.remove(dump)

        for attempt in (1, 2):
            text = _run_cli(["nfc-mfultralight", "r", dump], timeout=5)

            if "already claimed" in text or "Unable to open" in text:
                if attempt == 1:
                    clear_stuck_claim()
                    continue
                raise RuntimeError("NFC device busy (replug reader and retry)")

            if "ERROR" in text:
                return None
            if not (os.path.exists(dump) and os.path.getsize(dump) >= 540):
                return None

            with open(dump, "rb") as f:
                data = f.read()
            uid = " ".join(f"{b:02x}" for b in (data[0:3] + data[4:8]))
            return uid, data
        return None
