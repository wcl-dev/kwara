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

The design is that THE HASHES GO IN GIT AND THE DATA DOES NOT: a reviewer can
establish that a corpus file is byte-for-byte the one the manifest records,
without the repository ever carrying the third-party data itself.

WHAT ESTABLISHES *WHEN*, AND WHAT DOES NOT. A commit hash binds content once
that content is independently known. A commit DATE does not establish time —
it is self-asserted, and local history can be rewritten. Time has to come from
outside the repository: pushing to a remote nobody controls alone, an RFC 3161
timestamp over the manifest, or an organisational append-only record. Until
one of those exists, this manifest proves integrity, not age.

THE LIMITATION THIS MANIFEST RECORDS, AND DOES NOT FIX

kwara did not retain the raw response bodies of the ads.txt files behind THIS
corpus. The discovery sweep (`discovery.py`) reads the bytes, computes a
SHA-256, parses out the DIRECT accounts, and discards them; it has no
acquisitions write path and still has none.

The case pipeline no longer works that way. As of 2026-08-12 — after this
corpus was collected — `adstxt.py` hands the response bytes to its caller to
persist, and the evidence exporter ships them with the pack alongside
`ads_txt_json`, failing closed when a recorded body is missing from disk. A
recipient of a pack built from a case today CAN re-hash the ads.txt for
themselves. A recipient of this corpus cannot.

So for this corpus kwara's strongest binding signal — two domains serving a
byte-identical ads.txt — remains a claim a recipient must take on trust. They
cannot re-hash either file. Where the site has since started refusing requests, they
cannot re-fetch it either: blocked-site.example was observed on 2026-08-05 serving sha
3bb8f682471e (278 accounts, identical to sibling-site.example) and returned HTTP 403 the
following day.

This manifest makes the DERIVED artifacts tamper-evident. It does not turn
them into independently verifiable evidence, because the bytes they were
derived from no longer exist. And note the ceiling even after retention: two
identical ads.txt bodies prove identical captured bytes, not a common
operator — platform-generated templates are common, which the clustering code
already guards against. Retaining response bytes at acquisition was a change
to the collection path, not something a hashing script could supply after the
fact; it landed on 2026-08-12. A template match drawn from THIS corpus still
has to be reported as an observation with a stated provenance limitation,
because the bytes behind it were never kept. One drawn from a case collected
since does not.
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
    "Raw ads.txt response bodies were NOT retained by the discovery screening "
    "path that produced this corpus. discovery.py hashes and parses the bytes, "
    "then discards them, and has no acquisitions write path; ads_txt_json "
    "stores raw_sha256 and parsed records only. The case pipeline is different "
    "since 2026-08-12: adstxt.py hands the body on for its caller to persist. "
    "That does not reach back to this corpus.",
    "A template match therefore cannot be re-verified from this corpus. The "
    "hashes here establish that the DERIVED observations have not changed "
    "since this manifest was written; they cannot establish that the "
    "original fetch was hashed or attributed correctly, nor WHEN the "
    "observation was made — the manifest proves integrity, not age.",
    "CORRECTED 2026-08-28, was wrong from 2026-08-12: this list used to state "
    "that the evidence exporter carries no ads.txt evidence. exporter.py "
    "selects ads_txt_json into urls/scan_runs.csv and ships the acquisition "
    "response bytes with the pack, failing closed when a recorded body is "
    "missing from disk. This concerns packs built from a case database, never "
    "this corpus.",
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


def build(root: str, limitations: list | None = None) -> dict:
    files = []
    total = 0
    for full in _walk(root):
        size = os.path.getsize(full)
        total += size
        files.append({
            "path": os.path.relpath(full, root),
            "bytes": size,
            "sha256": _sha256(full),
            # Filesystem mtime: self-reported, trivially settable, and NOT
            # the time of acquisition. Informational only.
            "fs_mtime_informational": datetime.fromtimestamp(
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
        "provenance_limitations": (
            PROVENANCE_LIMITATIONS if limitations is None else limitations),
        "files": files,
    }


def verify(root: str, manifest_path: str, *, allow_added: bool = False) -> int:
    try:
        with open(manifest_path, encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as exc:
        print(f"cannot read manifest: {exc}")
        return 2

    recorded = {f["path"]: f for f in manifest.get("files", [])}
    # _walk already refuses symlinks. Membership in THAT set is the test, not
    # os.path.isfile — which follows a link, so a recorded file replaced by a
    # symlink would otherwise be hashed through to wherever it now points.
    on_disk = {os.path.relpath(p, root) for p in _walk(root)}

    changed, missing, added = [], [], sorted(on_disk - set(recorded))
    for rel, entry in sorted(recorded.items()):
        if rel not in on_disk:
            missing.append(rel)
            continue
        if _sha256(os.path.join(root, rel)) != entry["sha256"]:
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
    # An untracked file means the corpus is not the snapshot that was
    # committed. Returning success while printing UNTRACKED tells a human one
    # thing and automation another.
    return 1 if (changed or missing or (added and not allow_added)) else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--dir", default="discovery",
                    help="corpus directory (default: discovery)")
    ap.add_argument("--verify", action="store_true",
                    help="re-hash and compare against the existing manifest")
    ap.add_argument("--allow-added", action="store_true",
                    help="with --verify, treat new files as acceptable rather "
                         "than as a mismatch (they still print)")
    args = ap.parse_args()

    root = os.path.abspath(args.dir)
    if not os.path.isdir(root):
        print(f"no such directory: {root}")
        return 2
    manifest_path = os.path.join(root, MANIFEST_NAME)

    if args.verify:
        return verify(root, manifest_path, allow_added=args.allow_added)

    # PROVENANCE_LIMITATIONS are claims about the DISCOVERY corpus specifically.
    # Generating a manifest for some other directory must not inherit them —
    # that would stamp another corpus with a history it does not have.
    is_discovery = os.path.basename(root) == "discovery"
    manifest = build(root, None if is_discovery else [])
    if not is_discovery:
        print(f"note: {root} is not the discovery corpus, so no provenance "
              f"limitations were recorded. Supply them yourself if it has any.")


    with open(manifest_path, "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
    print(f"{manifest['file_count']} files, "
          f"{manifest['total_bytes'] / 2 ** 20:.1f} MB")
    print(f"written to {manifest_path}")
    print("\nCommit the manifest. Do NOT commit the corpus.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
