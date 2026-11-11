"""runtime - Runtime paths shared by all tools (mirrors hook-side badge_dir_path)

Priority: SKY_BADGE_DIR env var, then user config dir
  Linux:   ~/.config/sky-badge/
  Windows: %APPDATA%\\sky-badge

Under Proton, the LD_PRELOAD directory is bind-mounted read-only inside the
game sandbox, so the hook probes writability and falls back to the config
dir. The Python tools therefore probe BOTH locations.
"""
import json
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


def app_dir():
    """Directory of the running exe (frozen) or the source tree."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return PROJECT_ROOT


def config_paths():
    """External editable config first (frozen), bundled copy second."""
    paths = []
    if getattr(sys, "frozen", False):
        paths.append(os.path.join(app_dir(), "config.json"))
    paths.append(os.path.join(PROJECT_ROOT, "config.json"))
    return paths


def load_config():
    for cfg_path in config_paths():
        try:
            with open(cfg_path, encoding="utf-8") as f:
                return json.load(f)
        except (OSError, ValueError):
            continue
    return {}


def runtime_dirs():
    """Runtime directories to probe, in priority order"""
    dirs = []
    env = os.environ.get("SKY_BADGE_DIR")
    if env:
        dirs.append(env)
    if sys.platform == "win32":
        dirs.append(os.path.join(os.environ.get("APPDATA", "."), "sky-badge"))
    else:
        xdg = os.environ.get("XDG_CONFIG_HOME")
        if xdg:
            dirs.append(os.path.join(xdg, "sky-badge"))
        dirs.append(os.path.join(os.path.expanduser("~"), ".config", "sky-badge"))
    seen = []
    for d in dirs:
        if d not in seen:
            seen.append(d)
    return seen


def find_runtime_file(name):
    """Return the path of a runtime file if present in any runtime dir"""
    for d in runtime_dirs():
        p = os.path.join(d, name)
        if os.path.exists(p):
            return p
    return None


def primary_runtime_dir():
    """First candidate dir; writable on the tool side"""
    return runtime_dirs()[0]


def badge_dump_path():
    """NFC dump file inside the runtime dir"""
    cfg = load_config()
    name = cfg.get("nfc", {}).get("badge_dump", "badge.mfd")
    d = primary_runtime_dir()
    os.makedirs(d, exist_ok=True)
    return os.path.join(d, name)
