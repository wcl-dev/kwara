"""The package as a recipient receives it.

Everything else in the suite runs against the working tree with an editable
install, which hides exactly the failures packaging introduces: a module left
out of the wheel, a data file that is not data, an entry point that does not
resolve. `kwara/_snapshot_worker.py` is the sharp case — it is Python that must
ship as package DATA, because it is launched by path rather than imported.
"""
import os
import subprocess
import sys
import zipfile

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture(scope="module")
def wheel(tmp_path_factory):
    out = tmp_path_factory.mktemp("wheel")
    proc = subprocess.run(
        [sys.executable, "-m", "pip", "wheel", "--no-deps", "-w", str(out), REPO],
        capture_output=True, text=True, timeout=600)
    if proc.returncode != 0:
        pytest.skip(f"could not build a wheel here: {proc.stderr[-400:]}")
    wheels = list(out.glob("kwara-*.whl"))
    assert wheels, proc.stdout[-400:]
    return wheels[0]


@pytest.mark.slow
def test_every_module_ships(wheel):
    with zipfile.ZipFile(wheel) as z:
        names = {n for n in z.namelist() if n.endswith(".py")}
    src = {f"kwara/{f}" for f in os.listdir(os.path.join(REPO, "kwara"))
           if f.endswith(".py")}
    missing = sorted(src - names)
    assert not missing, f"modules missing from the wheel: {missing}"


@pytest.mark.slow
def test_the_subprocess_worker_is_inside_the_wheel(wheel):
    """It is launched by path from snapshots.py. Dropped from the wheel, every
    capture on an installed copy fails with 'no result file' and nothing says
    why."""
    with zipfile.ZipFile(wheel) as z:
        assert "kwara/_snapshot_worker.py" in z.namelist()


@pytest.mark.slow
def test_the_utils_subpackage_ships(wheel):
    with zipfile.ZipFile(wheel) as z:
        names = z.namelist()
    assert "kwara/utils/__init__.py" in names
    assert "kwara/utils/domain.py" in names


@pytest.mark.slow
def test_console_script_is_declared(wheel):
    with zipfile.ZipFile(wheel) as z:
        entry = [n for n in z.namelist() if n.endswith("entry_points.txt")]
        assert entry, "no entry_points.txt in the wheel"
        body = z.read(entry[0]).decode()
    assert "kwara = kwara.cli:main" in body.replace(" ", "").replace("kwara=", "kwara = ")


def test_installed_console_script_runs():
    exe = os.path.join(REPO, ".venv", "bin", "kwara")
    if not os.path.exists(exe):
        pytest.skip("kwara not installed into this venv")
    proc = subprocess.run([exe, "--help"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0
    assert "discover" in proc.stdout


def test_no_module_imports_the_removed_ui_dependencies():
    """streamlit and pandas went with the UI. A stray import passes on a dev
    machine that still has them in its venv and breaks a fresh install."""
    for root, _dirs, files in os.walk(os.path.join(REPO, "kwara")):
        for f in files:
            if not f.endswith(".py"):
                continue
            src = open(os.path.join(root, f), encoding="utf-8").read()
            for banned in ("import streamlit", "import pandas"):
                assert banned not in src, f"{f} still has `{banned}`"


def test_no_sys_path_manipulation_survives_in_the_package():
    """The flat-import era. Any of these left behind means a module is still
    relying on the package directory being on sys.path."""
    offenders = []
    for root, _dirs, files in os.walk(os.path.join(REPO, "kwara")):
        for f in files:
            if f.endswith(".py"):
                src = open(os.path.join(root, f), encoding="utf-8").read()
                if "sys.path.insert" in src:
                    offenders.append(f)
    assert not offenders, offenders


def test_declared_dependencies_agree_with_requirements():
    """pyproject and requirements.txt are maintained separately and will
    drift; the README installs from one and pip install from the other."""
    import tomllib
    with open(os.path.join(REPO, "pyproject.toml"), "rb") as fh:
        proj = tomllib.load(fh)
    declared = {d.split(">")[0].split("=")[0].strip().lower()
                for d in proj["project"]["dependencies"]}
    req = set()
    with open(os.path.join(REPO, "requirements.txt"), encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                req.add(line.split(">")[0].split("=")[0].strip().lower())
    assert declared == req, f"pyproject={sorted(declared)} requirements={sorted(req)}"
