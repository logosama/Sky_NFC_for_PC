#!/usr/bin/env python3
"""Sky 徽章注入控制——Unix socket 客户端"""
import sys
import os
import time
import glob
import socket

SOCK_PATTERN = "/tmp/sky_inject.sock.*"
LOG_PATH = "/tmp/sky_inject.log"


def find_sockets():
    return sorted(glob.glob(SOCK_PATTERN))


def find_main():
    """查找主游戏进程（回复 main=1）"""
    for path in find_sockets():
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(path)
            s.sendall(b"ping")
            resp = s.recv(1024).decode()
            s.close()
            if "main=1" in resp:
                return path, resp
        except Exception:
            pass
    return None, None


def send_cmd(cmd: str) -> str:
    path, info = find_main()
    if not path:
        print("No main Sky.exe process found.")
        return ""
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect(path)
        s.sendall(cmd.encode() + b"\n")
        resp = s.recv(8192).decode().strip()
        s.close()
        return resp
    except Exception as e:
        print(f"Error: {e}")
        return ""


def tail_log(n=30):
    if not os.path.exists(LOG_PATH):
        return
    with open(LOG_PATH) as f:
        lines = f.readlines()
    for line in lines[-n:]:
        print(line.rstrip())


def main():
    if len(sys.argv) < 2:
        print("Sky 徽章注入控制")
        print()
        print("  ping             - 测试连接/状态")
        print("  hook             - 安装游戏线程 hook")
        print("  unhook           - 卸载 hook")
        print("  inject <url>     - 排队注入徽章 URL（游戏线程执行）")
        print("  count            - hook 调用计数")
        print("  log [N]          - 查看日志")
        print()
        print("Steam 启动选项:")
        print("  LD_PRELOAD=/home/miku/Games/Sky/sky_hook.so %command%")
        return

    cmd = sys.argv[1]

    if cmd == "ping":
        path, info = find_main()
        print(f"  {info}" if path else "  Not found")

    elif cmd == "hook":
        print("Installing hook...")
        print(f"  {send_cmd('hook')}")

    elif cmd == "unhook":
        print(f"  {send_cmd('unhook')}")

    elif cmd == "inject":
        if len(sys.argv) < 3:
            print("Usage: skyctl.py inject <url>")
            return
        print(f"  {send_cmd('inject ' + sys.argv[2])}")

    elif cmd == "count":
        print(f"  {send_cmd('ping')}")

    elif cmd == "log":
        n = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        tail_log(n)

    else:
        print(f"Unknown: {cmd}")


if __name__ == "__main__":
    main()
