import os, shutil, tempfile, uuid
from pathlib import Path
from typing import Optional

KEY_DIR = Path(tempfile.gettempdir()) / "cyberorion_hostguard_keys"

def init() -> None:
    if KEY_DIR.is_dir():
        shutil.rmtree(KEY_DIR, ignore_errors=True)
    _ensure_dir()

def save_key(content: bytes, original_name: str) -> Path:
    _ensure_dir()
    safe_name = Path(original_name).name or "id_rsa"
    if not safe_name.strip():
        safe_name = "id_rsa"
    target = KEY_DIR / (uuid.uuid4().hex + "_" + safe_name)
    target.write_bytes(content)
    os.chmod(target, 0o600)
    return target


def _ensure_dir() -> Path:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(KEY_DIR, 0o700)
    return KEY_DIR


def remove_key(path):
    if not path:
        return
    try:
        p = Path(path)
        if p.is_file() and p.parent == KEY_DIR:
            p.unlink()
    except OSError:
        pass


def cleanup_all():
    if not KEY_DIR.is_dir():
        return
    for f in KEY_DIR.iterdir():
        try:
            f.unlink()
        except OSError:
            pass
