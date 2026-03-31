"""讓測試能以 `kwara/` 為套件根目錄匯入模組。"""
import sys
from pathlib import Path

_KWARA = Path(__file__).resolve().parent.parent / "kwara"
_p = str(_KWARA)
if _p not in sys.path:
    sys.path.insert(0, _p)
