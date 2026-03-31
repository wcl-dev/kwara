import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent


def test_whois_domain_lookup_help_exits_zero():
    script = _ROOT / "whois_osint" / "whois_domain_lookup.py"
    r = subprocess.run(
        [sys.executable, str(script), "-h"],
        cwd=str(_ROOT / "whois_osint"),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0
    out = (r.stdout or "") + (r.stderr or "")
    assert "usage" in out.lower() or "WHOIS" in out
