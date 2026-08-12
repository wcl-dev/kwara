#!/usr/bin/env python3
"""Hash the discovery corpus so its integrity can be checked later.

    python corpus_manifest.py                      # write the manifest
    python corpus_manifest.py --verify             # re-hash and compare
    python corpus_manifest.py --dir some/other/dir

WHY THIS EXISTS

`discovery/` holds sweep results that cannot be rebuilt: 10,167 candidate
domains screened across two rounds in 2026-08, the reference population of
5,232 third-party sites' ads.txt accounts that the ad-account tier logic reads
at analysis time, and the byte-identical-template observations that produced
two of the open cases. It is gitignored, correctly — it is other people's data
and does not belong in a public repository — but "gitignored" had come to mean
"unversioned, unhashed, and backed up nowhere".

The design is that THE HASHES GO IN GIT AND THE DATA DOES NOT. A commit is a
timestamp nobody can quietly move, so a reviewer can establish that a corpus
file is byte-for-byte what it was on the date the manifest was committed —
without the repository ever carrying the third-party data itself.

THE LIMITATION THIS MANIFEST RECORDS, AND DOES NOT FIX

kwara did not retain the raw response bodies of the ads.txt files it fetched.
Both the discovery sweep (`discovery.py`) and the case pipeline (`adstxt.py`)
read the bytes, compute a SHA-256, parse out the DIRECT accounts, and discard
the bytes. `ads_txt_json` on a scan_run stores `raw_sha256` and the parsed
records; there is no `raw` field. The evidence exporter does not export
`ads_txt_json` at all.

So kwara's strongest binding signal — two domains serving a byte-identical
ads.txt — is, today, a claim a recipient must take on trust. They cannot
re-hash either file. Where the site has since started refusing requests, they
cannot re-fetch it either: blockedsite.example was observed on 2026-08-05 serving sha
3bb8f682471e (278 accounts, identical to siblingsite.example) and returned HTTP 403 the
following day.

This manifest makes the DERIVED artifacts tamper-evident. It does not turn
them into independently verifiable evidence, because the bytes they were
derived from no longer exist. Retaining response bytes at acquisition is a
change to the collection path, not something a hashing script can supply after
the fact. Until that lands, an ads.txt template match should be reported as an
observation with a stated provenance limitation.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

MANIFEST_NAME = "CORPUS-MANIFEST.json"
SCHEMA = "kwara-corpus-manifest/1"

# Recorded in the manifest so it travels with the hashes rather than living
# only in a commit message someone has to go looking for.
PROVENANCE_LIMITATIONS = [
    "Raw ads.txt response bodies were NOT retained. discovery.py and adstxt.py "
    "hash and parse the bytes, then discard them; ads_txt_json stores "
    "raw_sha256 and parsed records only.",
    "A template match therefore cannot be re-verified from this corpus. The "
    "hashes here establish that the DERIVED observations have not changed "
    "since this manifest was committed; they cannot establish that the "
    "original fetch was hashed or attributed correctly.",
    "The evidence exporter does not include ads_txt_json, so an export pack "
    "carries no ads.txt evidence at all.",
    "reference_prevalence.json declares all 8 SSPs in its source field, but "
    "its 5,232 sites are round-1 only — run_round2.py stripped records before "
    "writing. The provenance field is wrong; the data is round 1.",
]


def _sha256(path: str) -> str:
    d = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            d.update(block)
    return d.hexdigest()


def _walk(root: str) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in sorted(dirnames) if d != "__pycache__"]
        for name in sorted(filenames):
            if name == MANIFEST_NAME:
                continue
            full = os.path.join(dirpath, name)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            out.append(full)
    return out


def build(root: str) -> dict:
    files = []
    total = 0
    for full in _walk(root):
        size = os.path.getsize(full)
        total += size
        files.append({
            "path": os.path.relpath(full, root),
            "bytes": size,
            "sha256": _sha256(full),
            "modified": datetime.fromtimestamp(
                os.path.getmtime(full), tz=timezone.utc
            ).strftime("%Y-%m-%d %H:%M:%S UTC"),
        })
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(tz=timezone.utc)
                                .strftime("%Y-%m-%d %H:%M:%S UTC"),
        "root": os.path.basename(os.path.abspath(root)),
        "file_count": len(files),
        "total_bytes": total,
        "provenance_limitations": PROVENANCE_LIMITATIONS,
        "files": files,
    }


def verify(root: str, manifest_path: str) -> int:
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"cannot read manifest: {exc}")
        return 2

    recorded = {f["path"]: f for f in manifest.get("files", [])}
    on_disk = {os.path.relpath(p, root) for p in _walk(root)}

    changed, missing, added = [], [], sorted(on_disk - set(recorded))
    for rel, entry in sorted(recorded.items()):
        full = os.path.join(root, rel)
        if not os.path.isfile(full):
            missing.append(rel)
            continue
        if _sha256(full) != entry["sha256"]:
            changed.append(rel)

    print(f"manifest  {manifest.get('generated_at')}  "
          f"{manifest.get('file_count')} files")
    print(f"unchanged {len(recorded) - len(changed) - len(missing)}")
    for label, rows in (("CHANGED", changed), ("MISSING", missing),
                        ("UNTRACKED", added)):
        if rows:
            print(f"{label:<9} {len(rows)}")
            for r in rows[:20]:
                print(f"    {r}")
    return 1 if (changed or missing) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default="discovery",
                    help="corpus directory (default: discovery)")
    ap.add_argument("--verify", action="store_true",
                    help="re-hash and compare against the existing manifest")
    args = ap.parse_args()

    root = os.path.abspath(args.dir)
    if not os.path.isdir(root):
        print(f"no such directory: {root}")
        return 2
    manifest_path = os.path.join(root, MANIFEST_NAME)

    if args.verify:
        return verify(root, manifest_path)

    manifest = build(root)
    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
    print(f"{manifest['file_count']} files, "
          f"{manifest['total_bytes'] / 2 ** 20:.1f} MB")
    print(f"written to {manifest_path}")
    print("\nCommit the manifest. Do NOT commit the corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
