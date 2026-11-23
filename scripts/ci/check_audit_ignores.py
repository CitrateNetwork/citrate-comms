#!/usr/bin/env python3
"""Keep the cargo-audit ignore list (.cargo/audit.toml) tied to deny.toml.

cargo audit scans every package in Cargo.lock; cargo deny checks the
feature-resolved graph that is compiled. Cargo.lock also lists optional
dependencies that are never enabled (a weak `dep?/feature` reference is enough),
so cargo audit can report crates that no build contains. This check allows
exactly two kinds of cargo-audit ignore and fails on anything else:

1. an entry of deny.toml `[advisories] ignore` (the reasoned acceptance);
2. an entry of LOCKFILE_ONLY below, whose crate is in Cargo.lock but not in the
   compiled graph (every workspace member, all features, all targets, normal +
   build + dev edges). These must NOT be in deny.toml: cargo deny is what fails
   if the crate becomes compiled.

It fails when deny.toml ignores something audit.toml does not, when audit.toml
ignores something unlisted, when a LOCKFILE_ONLY crate is compiled, and when a
LOCKFILE_ONLY crate has left Cargo.lock (stale: delete the entry).

Usage: check_audit_ignores.py [--self-test]
"""
import argparse
import subprocess
import sys
import tomllib

# advisory -> crate it is filed against
LOCKFILE_ONLY = {
    "RUSTSEC-2026-0330": "libcrux-kem",
    "RUSTSEC-2026-0331": "libcrux-kem",
    "RUSTSEC-2026-0124": "libcrux-chacha20poly1305",
    "RUSTSEC-2026-0209": "libcrux-aesgcm",
    "RUSTSEC-2026-0211": "libcrux-aesgcm",
}


def ignore_ids(cfg: dict) -> set[str]:
    out = set()
    for e in cfg.get("advisories", {}).get("ignore", []):
        out.add(e if isinstance(e, str) else e["id"])
    return out


def check(deny: set[str], audit: set[str], locked: set[str], compiled: set[str],
          lockfile_only: dict[str, str] = LOCKFILE_ONLY) -> list[str]:
    errors = []
    for a in sorted(deny - audit):
        errors.append(f"{a}: ignored in deny.toml but not in .cargo/audit.toml")
    for a in sorted(audit - deny - set(lockfile_only)):
        errors.append(f"{a}: ignored in .cargo/audit.toml with no deny.toml or lockfile-only entry")
    for a, crate in sorted(lockfile_only.items()):
        if a in deny:
            errors.append(f"{a}: lockfile-only advisory must not be ignored in deny.toml")
        if a not in audit:
            errors.append(f"{a}: listed as lockfile-only but not ignored in .cargo/audit.toml")
        if crate not in locked:
            errors.append(f"{a}: {crate} is no longer in Cargo.lock; the ignore is stale, remove it")
        elif crate in compiled:
            errors.append(f"{a}: {crate} is now compiled; it is not lockfile-only any more")
    return errors


def compiled_crates() -> set[str]:
    out = subprocess.run(
        ["cargo", "tree", "--locked", "--workspace", "--target", "all",
         "-e", "normal,build,dev", "--all-features", "--prefix", "none", "--format", "{p}"],
        check=True, capture_output=True, text=True).stdout
    return {line.split()[0] for line in out.splitlines() if line.strip()}


def self_test() -> None:
    deny = {"RUSTSEC-0000-0001"}
    lo = {"RUSTSEC-0000-0002": "kem"}
    audit = deny | set(lo)
    locked = {"kem", "sha3"}
    compiled = {"sha3"}
    cases = [
        ("consistent", (deny, audit, locked, compiled), 0),
        ("lockfile-only crate becomes compiled", (deny, audit, locked, compiled | {"kem"}), 1),
        ("lockfile-only crate left Cargo.lock", (deny, audit, {"sha3"}, compiled), 1),
        ("deny ignore missing from audit.toml", (deny | {"RUSTSEC-0000-0003"}, audit, locked, compiled), 1),
        ("unlisted audit.toml ignore", (deny, audit | {"RUSTSEC-0000-0004"}, locked, compiled), 1),
        ("lockfile-only also ignored in deny.toml", (deny | set(lo), audit, locked, compiled), 1),
        ("lockfile-only not in audit.toml", (deny, deny, locked, compiled), 1),
    ]
    bad = []
    for name, args, want in cases:
        got = len(check(*args, lockfile_only=lo))
        if got != want:
            bad.append(f"{name}: expected {want} failure(s), got {got}")
    if bad:
        print("self-test FAILED:", *bad, sep="\n  ")
        sys.exit(1)
    print(f"self-test: {len(cases)} cases pass")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        self_test()
        return
    with open("deny.toml", "rb") as f:
        deny = ignore_ids(tomllib.load(f))
    with open(".cargo/audit.toml", "rb") as f:
        audit = ignore_ids(tomllib.load(f))
    with open("Cargo.lock", "rb") as f:
        locked = {p["name"] for p in tomllib.load(f).get("package", [])}
    errors = check(deny, audit, locked, compiled_crates())
    if errors:
        print("cargo-audit ignore check failed:", *errors, sep="\n  ")
        sys.exit(1)
    print(f"cargo-audit ignores: {len(deny)} mirrored from deny.toml, "
          f"{len(LOCKFILE_ONLY)} lockfile-only (crates not compiled)")


if __name__ == "__main__":
    main()
