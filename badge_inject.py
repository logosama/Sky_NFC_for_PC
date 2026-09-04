#!/usr/bin/env python3
"""Sky 徽章注入工具
启动后输入 s 扫描徽章，自动读取 NDEF URL 并注入游戏（游戏线程处理）。
"""
import subprocess
import os
import sys
import time
import socket
import glob

BADGE_DUMP = "/tmp/badge.mfd"
SOCK_PATTERN = "/tmp/sky_inject.sock.*"
LOG_PATH = "/tmp/sky_inject.log"
SKY_LOG = os.path.expanduser("~/.steam/steam/steamapps/common/Sky Children of the Light/Sky.log")


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return ""


def find_main():
    for path in sorted(glob.glob(SOCK_PATTERN)):
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


def skyctl(cmd):
    """直接通过 socket 发送命令到 hook"""
    path, _ = find_main()
    if not path:
        return None
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(60)
        s.connect(path)
        s.sendall(cmd.encode() + b"\n")
        resp = s.recv(8192).decode().strip()
        s.close()
        return resp
    except Exception as e:
        return f"ERR {e}"


# ============ 徽章扫描 ============

def scan_badge():
    """轮询读取徽章（nfc-mfultralight 直读，徽章贴上即成功）"""
    if os.path.exists(BADGE_DUMP):
        os.remove(BADGE_DUMP)  # 删除旧 dump，防止误用旧数据（计数器防重放）
    deadline = time.time() + 35
    while time.time() < deadline:
        out = run(f"nfc-mfultralight r {BADGE_DUMP}", timeout=5)
        if "already claimed" in out or "Unable to open" in out:
            print("  ✗ 串口被占用。请重插 FT232 USB 后重试")
            return "PORT_BUSY"
        if ("ERROR" not in out and os.path.exists(BADGE_DUMP)
                and os.path.getsize(BADGE_DUMP) >= 540):  # NTAG215 = 540 字节
            with open(BADGE_DUMP, "rb") as f:
                data = f.read()
            uid = " ".join(f"{b:02x}" for b in (data[0:3] + data[4:8]))
            return uid
        time.sleep(0.5)
    return None


def parse_ndef(data):
    """解析 NTAG215 NDEF TLV，提取 URI（page 4 起）"""
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
    """解析 NDEF URI record（TNF=1, type='U'）"""
    if len(ndef) < 5:
        return None
    tnf = ndef[0] & 0x07
    type_len = ndef[1]
    payload_len = ndef[2] if (ndef[0] & 0x10) else int.from_bytes(ndef[2:6], "big")
    idx = 3 if (ndef[0] & 0x10) else 6
    rec_type = ndef[idx:idx + type_len]
    payload = ndef[idx + type_len:idx + type_len + payload_len]
    if tnf == 1 and rec_type == b"U":
        prefixes = {0x00: "", 0x01: "http://www.", 0x02: "https://www.",
                    0x03: "http://", 0x04: "https://"}
        return prefixes.get(payload[0], "") + payload[1:].decode("utf-8", errors="replace")
    return None


# ============ 游戏注入 ============

def inject_url(url):
    """hook 消息分发器 → inject 排队 → 游戏线程自动执行"""
    ping = skyctl("ping") or ""
    if "hook=0" in ping:
        print("  [注入] 安装 hook...")
        skyctl("hook")
        time.sleep(0.5)

    print("  [注入] 排队 URL（游戏线程将自动执行）...")
    print(f"  [注入] {skyctl(f'inject {url}')}")

    time.sleep(3)  # 等待消息分发器触发注入
    with open(LOG_PATH) as f:
        log = f.read()
    if "INJECT done" in log:
        print("  [结果] ✓ 注入执行成功！")
        if os.path.exists(SKY_LOG):
            print(f"  [游戏日志] {run(f'grep OnOpenedWithURL \"{SKY_LOG}\" | tail -2').strip()}")
    else:
        print("  [结果] 注入未执行（检查 /tmp/sky_inject.log）")


# ============ 主循环 ============

def main():
    print("=" * 60)
    print("  Sky 徽章注入工具")
    print("=" * 60)

    path, info = find_main()
    if path:
        print(f"✓ hook 已加载 ({info})")
    else:
        print("⚠ 游戏/hook 未就绪。检查 Steam 启动选项:")
        print("  LD_PRELOAD=/home/miku/Games/Sky/sky_hook.so %command%")

    print()
    print("指令:  s/scan 扫描徽章并注入 | h 帮助 | q 退出")
    print()

    while True:
        try:
            cmd = input("sky> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print("\n再见!")
            break

        if cmd in ("q", "quit", "exit"):
            print("再见!")
            break
        elif cmd in ("h", "help", ""):
            print("  s/scan  扫描徽章并注入")
            print("  q/quit  退出")
        elif cmd in ("s", "scan"):
            print("  [扫描] 请将徽章贴近读卡器...（30秒窗口，保持贴住）")
            uid = scan_badge()
            if uid == "PORT_BUSY":
                continue
            if not uid:
                print("  ✗ 未检测到徽章")
                continue
            print(f"  ✓ 发现徽章 UID: {uid}")

            with open(BADGE_DUMP, "rb") as f:
                data = f.read()
            url = parse_ndef(data)
            if not url:
                print("  ✗ NDEF 解析失败（查看 /tmp/badge.mfd）")
                continue
            print(f"  ✓ NDEF URL: {url[:70]}...")

            inject_url(url)
        else:
            print(f"  未知指令: {cmd}")


if __name__ == "__main__":
    main()
