"""語法檢查：確保主要目錄可編譯。"""
import compileall
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_kwara_sources_compile():
    ok_kwara = compileall.compile_dir(_ROOT / "kwara", quiet=1, legacy=True)
    assert ok_kwara
