"""injector.py - Windows DLL injector (ctypes calling kernel32, zero deps)
Flow: OpenProcess -> VirtualAllocEx -> WriteProcessMemory(DLL path) -> CreateRemoteThread(LoadLibraryA)
Usage: python3 injector.py [process name] [DLL path]
"""
import ctypes
import ctypes.wintypes as wt
import os
import sys

PROCESS_ALL_ACCESS = 0x001F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
user32 = ctypes.WinDLL("user32", use_last_error=True)


def _setup():
    kernel32.OpenProcess.restype = wt.HANDLE
    kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
    kernel32.VirtualAllocEx.restype = wt.LPVOID
    kernel32.VirtualAllocEx.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.DWORD, wt.DWORD]
    kernel32.WriteProcessMemory.restype = wt.BOOL
    kernel32.WriteProcessMemory.argtypes = [wt.HANDLE, wt.LPVOID, wt.LPCVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    kernel32.CreateRemoteThread.restype = wt.HANDLE
    kernel32.CreateRemoteThread.argtypes = [wt.HANDLE, wt.LPVOID, ctypes.c_size_t, wt.LPVOID, wt.LPVOID, wt.DWORD, wt.LPVOID]
    kernel32.WaitForSingleObject.restype = wt.DWORD
    kernel32.WaitForSingleObject.argtypes = [wt.HANDLE, wt.DWORD]
    kernel32.CloseHandle.restype = wt.BOOL
    kernel32.CloseHandle.argtypes = [wt.HANDLE]
    kernel32.GetModuleHandleA.restype = wt.HMODULE
    kernel32.GetModuleHandleA.argtypes = [wt.LPCSTR]
    kernel32.GetProcAddress.restype = wt.LPVOID
    kernel32.GetProcAddress.argtypes = [wt.HMODULE, wt.LPCSTR]
    user32.EnumWindows.restype = wt.BOOL
    user32.EnumWindows.argtypes = [wt.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM), wt.LPARAM]
    user32.GetWindowThreadProcessId.restype = wt.DWORD
    user32.GetWindowThreadProcessId.argtypes = [wt.HWND, ctypes.POINTER(wt.DWORD)]


def find_pid_by_name(proc_name):
    """Find PID by process name (system snapshot, no psutil dependency)"""
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    # Toolhelp32 is more reliable
    kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE
    kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
    kernel32.Process32FirstW.restype = wt.BOOL
    kernel32.Process32NextW.restype = wt.BOOL

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_wchar * 260),
        ]

    TH32CS_SNAPPROCESS = 0x2
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap:
        return None
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    result = None
    if kernel32.Process32FirstW(snap, ctypes.byref(entry)):
        while True:
            if entry.szExeFile.lower() == proc_name.lower():
                result = entry.th32ProcessID
                break
            if not kernel32.Process32NextW(snap, ctypes.byref(entry)):
                break
    kernel32.CloseHandle(snap)
    return result


def inject(pid, dll_path):
    """Inject DLL into target process"""
    _setup()
    dll_path_abs = os.path.abspath(dll_path)
    if not os.path.exists(dll_path_abs):
        print(f"Error: DLL not found: {dll_path_abs}")
        return False

    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        print(f"Error: OpenProcess failed (code {ctypes.get_last_error()})")
        return False

    dll_bytes = dll_path_abs.encode("ascii") + b"\x00"
    buf = kernel32.VirtualAllocEx(h_proc, None, len(dll_bytes), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    if not buf:
        print(f"Error: VirtualAllocEx failed (code {ctypes.get_last_error()})")
        kernel32.CloseHandle(h_proc)
        return False

    written = ctypes.c_size_t()
    if not kernel32.WriteProcessMemory(h_proc, buf, dll_bytes, len(dll_bytes), ctypes.byref(written)):
        print(f"Error: WriteProcessMemory failed (code {ctypes.get_last_error()})")
        kernel32.CloseHandle(h_proc)
        return False

    h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
    loadlib = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
    if not loadlib:
        print("Error: LoadLibraryA not found")
        kernel32.CloseHandle(h_proc)
        return False

    h_thread = kernel32.CreateRemoteThread(h_proc, None, 0, loadlib, buf, 0, None)
    if not h_thread:
        print(f"Error: CreateRemoteThread failed (code {ctypes.get_last_error()})")
        kernel32.CloseHandle(h_proc)
        return False

    kernel32.WaitForSingleObject(h_thread, INFINITE)
    kernel32.CloseHandle(h_thread)
    kernel32.CloseHandle(h_proc)
    print(f"OK: DLL injected: {dll_path_abs}")
    return True


def main():
    proc_name = sys.argv[1] if len(sys.argv) > 1 else "Sky.exe"
    dll_path = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "sky_hook.dll")

    pid = find_pid_by_name(proc_name)
    if not pid:
        print(f"Error: process not found: {proc_name} (game not running?)")
        sys.exit(1)
    print(f"Found {proc_name} PID={pid}")
    if not inject(pid, dll_path):
        sys.exit(1)


if __name__ == "__main__":
    main()
