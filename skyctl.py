#!/usr/bin/env python3
"""skyctl - Sky badge injection control client (cross-platform, TCP to hook)
Usage: python3 skyctl.py <ping|hook|unhook|inject|log>
"""
import os
import socket
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def runtime_dir():
    env = os.environ.get("SKY_BADGE_DIR")
    if env:
        return env
    if sys.platform == "win32":
        return os.path.join(os.environ.get("APPDATA", "."), "sky-badge")
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return os.path.join(xdg, "sky-badge")
    return os.path.join(os.path.expanduser("~"), ".config", "sky-badge")


def ipc_port():
    port_file = os.path.join(runtime_dir(), "ipc_port")
    for _ in range(50):
        try:
            with open(port_file) as f:
                return int(f.read().strip())
        except (FileNotFoundError, ValueError):
            time.sleep(0.1)
    return None


def send(cmd, timeout=30):
    port = ipc_port()
    if not port:
        print("hook not running (port file missing)")
        return ""
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.sendall(cmd.encode() + b"\n")
        resp = s.recv(8192).decode(errors="replace").strip()
        s.close()
        return resp
    except OSError as e:
        print(f"Error: {e}")
        return ""


def tail_log(n=30):
    log_file = os.path.join(runtime_dir(), "hook.log")
    if not os.path.exists(log_file):
        print("no log")
        return
    with open(log_file) as f:
        lines = f.readlines()
    for line in lines[-n:]:
        print(line.rstrip())


def main():
    if len(sys.argv) < 2:
        print("Sky Badge Injection Control")
        print()
        print("  ping          - status")
        print("  hook          - install hook")
        print("  unhook        - uninstall hook")
        print("  inject <url>  - queue injection")
        print("  log [N]       - view log")
        return

    cmd = sys.argv[1]
    if cmd == "ping":
        print(f"  {send('ping')}")
    elif cmd == "hook":
        print(f"  {send('hook')}")
    elif cmd == "unhook":
        print(f"  {send('unhook')}")
    elif cmd == "inject":
        if len(sys.argv) < 3:
            print("usage: skyctl.py inject <url>")
            return
        print(f"  {send('inject ' + sys.argv[2])}")
    elif cmd == "log":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        tail_log(n)
    else:
        print(f"unknown command: {cmd}")


if __name__ == "__main__":
    main()
