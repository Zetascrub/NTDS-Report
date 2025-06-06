#!/usr/bin/env python3
"""NTLM password statistics generator.

The script parses a file with cracked NTLM hashes (``NTLM_HASH:password``)
and optionally a list of all domain hashes extracted from ``ntds.dmp``.  It
prints statistics to ``stdout`` and writes the same information to a report
file.
"""

from __future__ import annotations

import argparse
import collections
import re
from pathlib import Path
from typing import Iterable, Iterator, Optional, Set

# ─── Helpers ──────────────────────────────────────────────────────────────────

DIGITS_RE = re.compile(r"\d+$")
TOP_WORD_RE = re.compile(r"^[A-Za-z]+")

def character_class(password: str) -> str:
    """Return a label describing the character classes used in ``password``."""

    classes = {
        "lower": bool(re.search(r"[a-z]", password)),
        "upper": bool(re.search(r"[A-Z]", password)),
        "num": bool(re.search(r"[0-9]", password)),
        "sym": bool(re.search(r"[^A-Za-z0-9]", password)),
    }

    key = (
        ("lower" if classes["lower"] and not classes["upper"] else
         "upper" if classes["upper"] and not classes["lower"] else
         "mixedalpha")
        + ("num" if classes["num"] else "")
        + ("special" if classes["sym"] else "")
    )

    return key or "other"

def first_cap_last_symbol(password: str) -> bool:
    """Check for an initial capital letter and a non-alphanumeric suffix."""

    return (
        len(password) >= 2
        and password[0].isupper()
        and not password[-1].isalnum()
    )

def first_cap_last_num(password: str) -> bool:
    """Check for an initial capital letter and a trailing digit."""

    return (
        len(password) >= 2
        and password[0].isupper()
        and password[-1].isdigit()
    )

# ─── Core ─────────────────────────────────────────────────────────────────────

def load_cracked(path: Path) -> Iterator[tuple[str, str]]:
    """Yield ``(hash, password)`` tuples from a cracked hash file."""

    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.rstrip()
            if ":" not in line:
                continue
            ntlm, plaintext = line.split(":", 1)
            yield ntlm.lower(), plaintext

def load_ntds(path: Path) -> Set[str]:
    """Return a set of NTLM hashes extracted from ``ntds.dmp``."""

    ntlm_hashes: Set[str] = set()
    with path.open(encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            parts = line.rstrip().split(":")
            if len(parts) > 3:
                ntlm = parts[3].lower()
                ntlm_hashes.add(ntlm)
    return ntlm_hashes

def generate_report(cracked_file: Path, ntds_file: Optional[Path] = None) -> str:
    """Return a formatted statistics report."""

    cracked = dict(load_cracked(cracked_file))
    total_cracked = len(cracked)

    if ntds_file:
        domain_hashes = load_ntds(ntds_file)
        cracked_pct = (total_cracked / len(domain_hashes))*100 if domain_hashes else 0

    # ─ Lengths ─
    length_counter = collections.Counter(len(pw) for pw in cracked.values())

    # ─ Base words (alphabetic prefix) ─
    base_counter = collections.Counter(
        TOP_WORD_RE.match(pw).group(0).lower()
        for pw in cracked.values()
        if TOP_WORD_RE.match(pw)
    )

    # ─ Patterns & character classes ─
    one_to_six = sum(1 for l in length_counter if l <= 6)
    one_to_eight = sum(1 for l in length_counter if l <= 8)
    gt_eight = total_cracked - one_to_eight

    fcls = sum(first_cap_last_symbol(pw) for pw in cracked.values())
    fcln = sum(first_cap_last_num(pw)    for pw in cracked.values())

    digit_suffix = collections.Counter(len(DIGITS_RE.findall(pw)[0])
                                       for pw in cracked.values()
                                       if DIGITS_RE.search(pw))

    last2 = collections.Counter(DIGITS_RE.search(pw).group()[-2:]
                               for pw in cracked.values()
                               if DIGITS_RE.search(pw) and len(DIGITS_RE.search(pw).group()) >= 2)

    last4 = collections.Counter(DIGITS_RE.search(pw).group()[-4:]
                               for pw in cracked.values()
                               if DIGITS_RE.search(pw) and len(DIGITS_RE.search(pw).group()) >= 4)

    last5 = collections.Counter(DIGITS_RE.search(pw).group()[-5:]
                               for pw in cracked.values()
                               if DIGITS_RE.search(pw) and len(DIGITS_RE.search(pw).group()) >= 5)

    char_sets = collections.Counter(character_class(pw) for pw in cracked.values())

    # ─── Print ───
    out = []
    if ntds_file:
        total_entries = len(domain_hashes)
        cracked_pct = (total_cracked / total_entries) * 100
        out.append(f"Total number of entries = {total_entries}")
        out.append(f"Total entries cracked = {total_cracked} / {total_entries} * 100 = {cracked_pct:.2f}%")
    else:
        out.append(f"Total cracked entries = {total_cracked}")

    out.append("\nTop 10 base words")
    for word, cnt in base_counter.most_common(10):
        out.append(f"{word:<10} = {cnt} ({cnt/total_cracked*100:.2f}%)")

    out.append("\nPassword length (count ordered)")
    for length, cnt in length_counter.most_common():
        out.append(f"{length:<2} = {cnt} ({cnt/total_cracked*100:.2f}%)")

    out.append(f"\nOne to six characters = {one_to_six} "
               f"({one_to_six/total_cracked*100:.2f}%)")
    out.append(f"One to eight characters = {one_to_eight} "
               f"({one_to_eight/total_cracked*100:.2f}%)")
    out.append(f"More than eight characters = {gt_eight} "
               f"({gt_eight/total_cracked*100:.2f}%)")

    out.append(f"\nFirst capital last symbol = {fcls} "
               f"({fcls/total_cracked*100:.2f}%)")
    out.append(f"First capital last number = {fcln} "
               f"({fcln/total_cracked*100:.2f}%)")

    out.append("\nSingle / double / triple digits on the end")
    for n in [1, 2, 3]:
        cnt = digit_suffix.get(n, 0)
        out.append(f"{n} digit{'s' if n>1 else ''} on the end = {cnt} "
                   f"({cnt/total_cracked*100:.2f}%)")

    def top(counter, label):
        out.append(f"\n{label} (Top 10)")
        for k, v in counter.most_common(10):
            out.append(f"{k:<5} = {v} ({v/total_cracked*100:.2f}%)")

    top(last2,  "Last 2 digits")
    top(last4,  "Last 4 digits")
    top(last5,  "Last 5 digits")

    out.append("\nCharacter sets")
    total = sum(char_sets.values())
    for k, v in char_sets.most_common():
        out.append(f"{k:<20}: {v} ({v/total*100:.2f}%)")

    return "\n".join(out)

def main(argv: Optional[Iterable[str]] = None) -> None:
    parser = argparse.ArgumentParser(description="Generate statistics for cracked NTLM hashes")
    parser.add_argument("cracked", type=Path, help="File containing NTLM_HASH:password pairs")
    parser.add_argument("ntds", nargs="?", type=Path, help="Optional ntds dump to calculate crack percentage")
    parser.add_argument("-o", "--output", type=Path, default=Path("report.txt"), help="Path to write the report (default: report.txt)")
    args = parser.parse_args(argv)

    report = generate_report(args.cracked, args.ntds)
    print(report)
    args.output.write_text(report)

if __name__ == "__main__":
    main()

