"""corpus_manifest.py — the hashes that make the discovery corpus tamper-evident.

`discovery/` holds sweep results that cannot be rebuilt and is gitignored,
correctly: it is other people's data. But gitignored had come to mean
unversioned, unhashed and backed up nowhere. The manifest goes in git and the
data does not. Note what that buys: INTEGRITY, not age — a commit date is
self-asserted and local history is rewritable, so *when* has to come from
outside the repo.

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


def test_an_added_file_fails_verification_by_default(corpus, capsys):
    """A new file means the corpus is not the snapshot that was recorded.
    Printing UNTRACKED while returning success tells a human one thing and any
    automation the opposite."""
    path = _write(corpus)
    (corpus / "data" / "round3.jsonl").write_text("{}\n", encoding="utf-8")

    assert cm.verify(str(corpus), path) == 1
    assert "UNTRACKED" in capsys.readouterr().out

    # New sweep output IS normal — it just has to be asked for explicitly.
    assert cm.verify(str(corpus), path, allow_added=True) == 0


def test_a_recorded_file_swapped_for_a_symlink_is_not_followed(corpus, tmp_path):
    """_walk refuses symlinks, but verify used os.path.isfile and then opened
    the path — both follow links. A recorded file replaced by a link would
    have been hashed through to wherever it now points, so an edit could hide
    behind the target."""
    path = _write(corpus)
    decoy = tmp_path / "decoy.md"
    decoy.write_text("# record\n", encoding="utf-8")     # identical content

    target = corpus / "FINDINGS.md"
    target.unlink()
    os.symlink(str(decoy), str(target))

    assert cm.verify(str(corpus), path) == 1, \
        "a symlink stood in for a recorded file and verification passed"


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


# The tracked manifest CREATES discovery/ on a fresh clone, so os.path.isdir is
# true there while all 20 corpus files are absent — the check would fail for
# everyone who has never run a sweep. Gate on the corpus data actually being
# present, not on the directory the manifest brings with it.
_HAS_CORPUS = os.path.isfile(os.path.join(REAL, "data",
                                          "reference_adstxt.jsonl.gz"))


@pytest.mark.skipif(not _HAS_CORPUS, reason="discovery corpus not on this machine")
def test_the_committed_manifest_still_matches_the_corpus():
    """Runs against the analyst's actual corpus when it is present. A red here
    means a file that cannot be rebuilt has changed since it was recorded."""
    path = os.path.join(REAL, cm.MANIFEST_NAME)
    if not os.path.isfile(path):
        pytest.skip("manifest not generated yet")
    assert cm.verify(REAL, path) == 0


def test_git_tracks_the_manifest_and_nothing_else_in_there():
    """The whole design in one assertion: hashes in, data out.

    Asked of git directly rather than by parsing `git add -An` output, whose
    wording is not a stable interface.
    """
    repo = os.path.dirname(REAL)
    if not os.path.isdir(os.path.join(repo, ".git")):
        pytest.skip("not a git checkout")

    listed = subprocess.run(["git", "ls-files", "discovery/"], cwd=repo,
                            capture_output=True, text=True)
    assert listed.returncode == 0
    assert listed.stdout.split() == [f"discovery/{cm.MANIFEST_NAME}"]

    # And the corpus itself must still be ignored. check-ignore exits 0 when
    # the path IS ignored, 1 when it is not.
    for rel in ("discovery/FINDINGS.md",
                "discovery/data/reference_adstxt.jsonl.gz"):
        r = subprocess.run(["git", "check-ignore", "-q", rel], cwd=repo)
        assert r.returncode == 0, f"{rel} is no longer ignored"

    r = subprocess.run(["git", "check-ignore", "-q",
                        f"discovery/{cm.MANIFEST_NAME}"], cwd=repo)
    assert r.returncode == 1, "the manifest is ignored and cannot be committed"
