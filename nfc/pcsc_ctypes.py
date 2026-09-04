"""PC/SC ctypes backend - cross-platform USB reader support (zero Python deps)
Linux: loads libpcsclite.so.1 (pcsclite system library)
Windows: loads winscard.dll (built-in)
Reads NTAG215 page by page via APDU (FF B0 00 <page> 04).
"""
import ctypes
import ctypes.util
import os
import sys

from nfc import badge_dump_path

# ============ PC/SC Constants ============
SCARD_SCOPE_USER = 0
SCARD_SHARE_SHARED = 2
SCARD_PROTOCOL_T0 = 1
SCARD_PROTOCOL_T1 = 2
SCARD_PCI_T0 = None
SCARD_E_NO_READERS_AVAILABLE = 0x8010002E
SCARD_E_NO_SMARTCARD = 0x8010000C
SCARD_S_SUCCESS = 0

# NTAG215: 135 pages, 4 bytes each
NTAG215_PAGES = 135


class PcscBackend:
    name = "pcsc"

    def __init__(self):
        self._lib = None
        self._load_lib()

    def _load_lib(self):
        """Load PC/SC library for current platform"""
        if sys.platform == "win32":
            try:
                self._lib = ctypes.WinDLL("winscard.dll")
            except OSError:
                self._lib = None
        else:
            for soname in ("libpcsclite.so.1", "libpcsclite.so"):
                try:
                    self._lib = ctypes.CDLL(soname)
                    break
                except OSError:
                    continue
        if self._lib:
            self._setup_signatures()

    def _setup_signatures(self):
        L = self._lib
        # Windows has A/W suffixes, Linux does not
        suffix = "A" if sys.platform == "win32" else ""
        self._f_connect = getattr(L, f"SCardConnect{suffix}")
        self._f_list_readers = getattr(L, f"SCardListReaders{suffix}")
        self._f_transmit = getattr(L, "SCardTransmit")
        self._f_disconnect = getattr(L, "SCardDisconnect")
        self._f_free_mem = getattr(L, "SCardFreeMemory", None)

        L.SCardEstablishContext.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        L.SCardEstablishContext.restype = ctypes.c_long
        self._f_list_readers.argtypes = [
            ctypes.c_uint32, ctypes.c_char_p,
            ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        self._f_list_readers.restype = ctypes.c_long
        self._f_connect.argtypes = [
            ctypes.c_uint32, ctypes.c_char_p, ctypes.c_uint32, ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32), ctypes.POINTER(ctypes.c_uint32),
        ]
        self._f_connect.restype = ctypes.c_long
        self._f_transmit.argtypes = [
            ctypes.c_uint32, ctypes.c_void_p,
            ctypes.c_void_p, ctypes.c_uint32,
            ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32),
        ]
        self._f_transmit.restype = ctypes.c_long
        self._f_disconnect.argtypes = [ctypes.c_uint32, ctypes.c_uint32]
        self._f_disconnect.restype = ctypes.c_long
        L.SCardReleaseContext.argtypes = [ctypes.c_uint32]
        L.SCardReleaseContext.restype = ctypes.c_long
        if self._f_free_mem:
            self._f_free_mem.argtypes = [ctypes.c_uint32, ctypes.c_void_p]
            self._f_free_mem.restype = ctypes.c_long

    def available(self):
        if not self._lib:
            return False
        ctx = ctypes.c_uint32()
        if self._lib.SCardEstablishContext(
                SCARD_SCOPE_USER, None, None, None, ctypes.byref(ctx)) != SCARD_S_SUCCESS:
            return False
        n = ctypes.c_uint32()
        rc = self._f_list_readers(ctx, None, None, ctypes.byref(n))
        self._lib.SCardReleaseContext(ctx)
        return rc == SCARD_S_SUCCESS and n.value > 0

    def read_once(self):
        """Attempt one badge read, returns (uid, ndef_bytes) or None"""
        if not self._lib:
            return None
        ctx = ctypes.c_uint32()
        if self._lib.SCardEstablishContext(
                SCARD_SCOPE_USER, None, None, None, ctypes.byref(ctx)) != SCARD_S_SUCCESS:
            return None
        try:
            return self._read_with_ctx(ctx)
        finally:
            self._lib.SCardReleaseContext(ctx)

    def _read_with_ctx(self, ctx):
        n = ctypes.c_uint32()
        rc = self._f_list_readers(ctx, None, None, ctypes.byref(n))
        if rc != SCARD_S_SUCCESS:
            return None
        buf = ctypes.create_string_buffer(n.value)
        rc = self._f_list_readers(ctx, None, buf, ctypes.byref(n))
        if rc != SCARD_S_SUCCESS or n.value < 2:
            return None
        reader = buf.value.decode("ascii", errors="replace")  # first reader (null-separated list)

        card = ctypes.c_uint32()
        proto = ctypes.c_uint32()
        if self._f_connect(
                ctx, reader.encode("ascii"), SCARD_SHARE_SHARED,
                SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                ctypes.byref(card), ctypes.byref(proto)) != SCARD_S_SUCCESS:
            return None

        try:
            data = bytearray()
            for page in range(NTAG215_PAGES):
                apdu = bytes([0xFF, 0xB0, 0x00, page & 0xFF, 0x04])  # READ 4 bytes
                resp = (ctypes.c_ubyte * 260)()
                resp_len = ctypes.c_uint32(len(resp))
                r = self._f_transmit(
                    card, None, apdu, len(apdu), None,
                    resp, ctypes.byref(resp_len))
                if r != SCARD_S_SUCCESS:
                    return None
                if resp_len.value < 4 or resp[resp_len.value - 2] != 0x90 or resp[resp_len.value - 1] != 0x00:
                    return None  # not 0x9000 success status
                data += bytes(resp[0:4])
            if len(data) < 540:
                return None
            uid = " ".join(f"{b:02x}" for b in (data[0:3] + data[4:8]))
            return uid, bytes(data)
        finally:
            self._f_disconnect(card, 0)


def save_dump(uid, data):
    dump = badge_dump_path()
    os.makedirs(os.path.dirname(dump), exist_ok=True)
    with open(dump, "wb") as f:
        f.write(data)
    return uid
