#!/usr/bin/env python3
"""Validate the MITRE ATT&CK technique IDs cited in the revika threat model.

Every threat sheet under ``security/<ID>/README.md`` carries a table:

    | Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
    | --- | --- | --- | --- |
    | Adversary-in-the-Middle | T1557 | ... | ... |

This script extracts every value in the ``ID`` column and checks it against the
official MITRE ATT&CK knowledge base loaded via ``mitreattack-python``. An ID
that no matrix knows is a hard error (typo or dropped technique); an ID that is
deprecated/revoked upstream is a warning (still valid, but worth migrating).

STIX bundles are read from ``--stix-dir`` (default ``$ATTACK_STIX_DIR`` or
``tools/.attack-stix``): any of ``enterprise-attack.json``, ``mobile-attack.json``,
``ics-attack.json`` present there is loaded. See tools/README.md for how to fetch
them locally; CI downloads them from mitre-attack/attack-stix-data.

Exit status: 0 = all IDs valid, 1 = at least one unknown ID, 2 = setup error
(no STIX bundle found / dependency missing).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path

# ATT&CK external_references source_name for the three matrices.
MITRE_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
STIX_FILES = ("enterprise-attack.json", "mobile-attack.json", "ics-attack.json")

# A technique ID: Txxxx, optionally a .yyy sub-technique.
ID_IN_CELL = re.compile(r"T\d{4}(?:\.\d{3})?")

REPO_ROOT = Path(__file__).resolve().parent.parent


def attack_external_id(obj) -> str | None:
    """Return an object's ATT&CK ID (e.g. 'T1557') from its external references."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in MITRE_SOURCES:
            return ref.get("external_id")
    return None


def load_known_ids(stix_dir: Path) -> tuple[set[str], set[str]]:
    """Load valid and deprecated/revoked technique IDs from the STIX bundles."""
    try:
        from mitreattack.stix20 import MitreAttackData
    except ImportError:
        sys.exit(
            "error: mitreattack-python is not installed "
            "(pip install -r tools/requirements.txt)"
        )

    bundles = [stix_dir / name for name in STIX_FILES if (stix_dir / name).is_file()]
    if not bundles:
        sys.exit(
            f"error: no ATT&CK STIX bundle found in {stix_dir} "
            f"(expected any of {', '.join(STIX_FILES)}); see tools/README.md"
        )

    valid: set[str] = set()
    deprecated: set[str] = set()
    for bundle in bundles:
        data = MitreAttackData(str(bundle))
        for tech in data.get_techniques(remove_revoked_deprecated=False):
            ext_id = attack_external_id(tech)
            if not ext_id:
                continue
            if tech.get("x_mitre_deprecated") or tech.get("revoked"):
                deprecated.add(ext_id)
            else:
                valid.add(ext_id)
    # A deprecated ID re-added as valid in another matrix should count valid.
    deprecated -= valid
    return valid, deprecated


def extract_ids(path: Path) -> list[tuple[int, str]]:
    """Return (lineno, id) pairs from the ATT&CK table's ID column in one file."""
    out: list[tuple[int, str]] = []
    id_col: int | None = None
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if not (line.startswith("|") and line.endswith("|")):
            id_col = None  # left the table
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if id_col is None:
            if "ID" in cells and "Technique ATT&CK" in cells:
                id_col = cells.index("ID")  # header row locates the column
            continue
        if cells and set("".join(cells)) <= set("-: "):
            continue  # separator row
        if id_col < len(cells):
            out.extend((lineno, m) for m in ID_IN_CELL.findall(cells[id_col]))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--security-dir",
        type=Path,
        default=REPO_ROOT / "security",
        help="root of the threat model (default: security/)",
    )
    parser.add_argument(
        "--stix-dir",
        type=Path,
        default=Path(os.environ.get("ATTACK_STIX_DIR", REPO_ROOT / "tools" / ".attack-stix")),
        help="directory holding the ATT&CK STIX bundles",
    )
    args = parser.parse_args()

    fiches = sorted(args.security_dir.glob("*/README.md"))
    if not fiches:
        sys.exit(f"error: no threat sheets found under {args.security_dir}")

    valid, deprecated = load_known_ids(args.stix_dir)

    errors: list[str] = []
    warnings: list[str] = []
    checked = 0
    for fiche in fiches:
        rel = fiche.relative_to(REPO_ROOT)
        for lineno, tid in extract_ids(fiche):
            checked += 1
            if tid in valid:
                continue
            if tid in deprecated:
                warnings.append(f"{rel}:{lineno}: {tid} is deprecated/revoked upstream")
            else:
                errors.append(f"{rel}:{lineno}: unknown ATT&CK ID {tid}")

    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")

    print(
        f"\nchecked {checked} ID references across {len(fiches)} threat sheets: "
        f"{len(errors)} unknown, {len(warnings)} deprecated"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
