"""corpus_manifest.py — the hashes that make the discovery corpus tamper-evident.

`discovery/` holds sweep results that cannot be rebuilt and is gitignored,
correctly: it is other people's data. But gitignored had come to mean
unversioned, unhashed and backed up nowhere. The manifest goes in git and the
data does not, so a commit date anchors the hashes.

These tests exist because a verifier that cannot fail is not a verifier — the
same lesson the `reconcile` source scan taught on 2026-08-11, where a
substring check silently passed on everything.
"""
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import corpus_manifest as cm


@pytest.fixture
def corpus(tmp_path):
    root = tmp_path / "corpus"
    (root / "data").mkdir(parents=True)
    (root / "FINDINGS.md").write_text("# record\n", encoding="utf-8")
    (root / "data" / "sweep.jsonl").write_text('{"domain":"a.test"}\n',
                                               encoding="utf-8")
    (root / "data" / "blob.bin").write_bytes(b"\x00\x01\x02" * 500)
    return root


def _write(root):
    manifest = cm.build(str(root))
    path = os.path.join(str(root), cm.MANIFEST_NAME)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh)
    return path


# ── building ──────────────────────────────────────────────────────────────

def test_every_file_is_hashed(corpus):
    m = cm.build(str(corpus))
    assert m["file_count"] == 3
    assert {f["path"] for f in m["files"]} == {
        "FINDINGS.md", os.path.join("data", "sweep.jsonl"),
        os.path.join("data", "blob.bin")}
    assert all(len(f["sha256"]) == 64 for f in m["files"])


def test_the_manifest_does_not_hash_itself(corpus):
    _write(corpus)
    assert cm.MANIFEST_NAME not in {f["path"] for f in cm.build(str(corpus))["files"]}


def test_the_provenance_limitation_travels_with_the_hashes(corpus):
    """The corpus's real weakness is that raw ads.txt bodies were never kept.
    That has to be recorded where the hashes are, not only in a commit message
    someone would have to go looking for — otherwise the manifest reads as a
    stronger guarantee than it is."""
    m = cm.build(str(corpus))
    joined = " ".join(m["provenance_limitations"]).lower()
    assert m["provenance_limitations"]
    assert "not retained" in joined or "discard" in joined
    assert "cannot be re-verified" in joined or "cannot" in joined


# ── verifying — each failure mode it must catch ───────────────────────────

def test_an_unchanged_corpus_verifies(corpus, capsys):
    assert cm.verify(str(corpus), _write(corpus)) == 0
    assert "unchanged 3" in capsys.readouterr().out


def test_a_changed_byte_is_caught(corpus, capsys):
    path = _write(corpus)
    f = corpus / "data" / "sweep.jsonl"
    f.write_text('{"domain":"EVIL.test"}\n', encoding="utf-8")

    assert cm.verify(str(corpus), path) == 1
    assert "CHANGED" in capsys.readouterr().out


def test_a_change_that_preserves_the_file_size_is_caught(corpus, capsys):
    """Size alone would not notice this. Hashing is the point."""
    path = _write(corpus)
    blob = corpus / "data" / "blob.bin"
    before = blob.stat().st_size
    data = bytearray(blob.read_bytes())
    data[7] ^= 0xFF
    blob.write_bytes(bytes(data))
    assert blob.stat().st_size == before

    assert cm.verify(str(corpus), path) == 1
    assert "CHANGED" in capsys.readouterr().out


def test_a_deleted_file_is_caught(corpus, capsys):
    path = _write(corpus)
    (corpus / "FINDINGS.md").unlink()
    assert cm.verify(str(corpus), path) == 1
    assert "MISSING" in capsys.readouterr().out


def test_an_added_file_is_reported_but_is_not_a_failure(corpus, capsys):
    """New sweep output is normal; silently absorbing it is not. It is named
    so the analyst knows to regenerate, and it does not fail the check."""
    path = _write(corpus)
    (corpus / "data" / "round3.jsonl").write_text("{}\n", encoding="utf-8")

    assert cm.verify(str(corpus), path) == 0
    assert "UNTRACKED" in capsys.readouterr().out


def test_a_missing_manifest_is_an_error_not_a_pass(corpus, capsys):
    assert cm.verify(str(corpus), str(corpus / "nope.json")) == 2


def test_symlinks_are_not_followed(corpus):
    """A link into the evidence store would otherwise pull it into the corpus
    hash set, and a link out of it would let an edit hide behind the target."""
    outside = corpus.parent / "outside.txt"
    outside.write_text("elsewhere", encoding="utf-8")
    os.symlink(str(outside), str(corpus / "linked.txt"))
    assert "linked.txt" not in {f["path"] for f in cm.build(str(corpus))["files"]}


# ── the real corpus ───────────────────────────────────────────────────────

REAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "discovery")


@pytest.mark.skipif(not os.path.isdir(REAL), reason="no discovery corpus here")
def test_the_committed_manifest_still_matches_the_corpus():
    """Runs against the analyst's actual corpus when it is present. A red here
    means a file that cannot be rebuilt has changed since it was committed."""
    path = os.path.join(REAL, cm.MANIFEST_NAME)
    if not os.path.isfile(path):
        pytest.skip("manifest not generated yet")
    assert cm.verify(REAL, path) == 0


@pytest.mark.skipif(not os.path.isdir(REAL), reason="no discovery corpus here")
def test_git_tracks_the_manifest_and_nothing_else_in_there():
    """The whole design in one assertion: hashes in, data out."""
    repo = os.path.dirname(REAL)
    out = subprocess.run(["git", "add", "-An", "discovery/"], cwd=repo,
                         capture_output=True, text=True)
    if out.returncode != 0:
        pytest.skip("not a git checkout")
    tracked = [ln.split("'")[1] for ln in out.stdout.splitlines() if "'" in ln]
    assert tracked == [f"discovery/{cm.MANIFEST_NAME}"], tracked
