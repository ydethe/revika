#!/usr/bin/env python3
"""Validate the framework IDs cited in the revika threat model.

Each threat sheet under ``security/<ID>/README.md`` carries two tables:

    ## Techniques MITRE ATT&CK et défenses
    | Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
    | Adversary-in-the-Middle | T1557 | ... | ... |

    ## Correspondance cadres de défense
    | Mesure de défense | Technique ATT&CK | D3FEND | NIST 800-53 |
    | Chiffrement client-side AES-256-GCM | T1530 | D3-MENCR | SC-28 |

The cadres table's ``Technique ATT&CK`` column names the ID(s) countered by each
defence and is validated the same way as the first table's ``ID`` column.

This script extracts every framework ID cited and checks it against the
official knowledge bases:

- **MITRE ATT&CK** (Enterprise + Mobile + ICS) via ``mitreattack-python`` — an
  ID no matrix knows is a hard error; a deprecated/revoked ID is a warning. The
  ATT&CK release is pinned to **v16.1** (not latest): each STIX bundle's
  ``x-mitre-collection`` version must be ``16.1`` or the check aborts as a setup
  error, so the model is validated against one stable knowledge base.
- **MITRE D3FEND** via the ontology JSON-LD — an unknown ``D3-XXXX`` id is an error.
- **NIST SP 800-53 Rev 5** via the OSCAL catalog — an unknown control id is an
  error. Enhancements accepted as ``SC-7(3)`` or ``SC-7.3`` (normalized to ``sc-7.3``).

A row in the cadres table with ``—`` in *both* framework columns is a warning
(the measure maps to no framework — usually a deliberate P2P state-of-the-art gap).

**Coverage:** every ATT&CK technique a fiche cites must be countered by at least one
defensive control — it has to appear in a cadres row carrying a D3FEND or NIST id.
A technique defended by no recognized control (or only by ``—``/``—`` gap rows) is a
hard error: an undefended threat in the model.

Datasets are read from ``--data-dir`` (default ``$FRAMEWORK_DATA_DIR`` or
``tools/.frameworks``): ATT&CK STIX bundles (``{enterprise,mobile,ics}-attack.json``),
``d3fend.json``, ``nist-sp800-53-rev5.json``. See tools/README.md for how to fetch
them; CI downloads them from the upstream projects.

Exit status: 0 = all IDs valid, 1 = at least one unknown ID, 2 = setup error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

MITRE_SOURCES = {"mitre-attack", "mitre-mobile-attack", "mitre-ics-attack"}
STIX_FILES = ("enterprise-attack.json", "mobile-attack.json", "ics-attack.json")
# Pin the ATT&CK release the model is validated against (not "latest").
ATTACK_VERSION = "16.1"
# The x-mitre-collection object leads each STIX bundle; its x_mitre_version is
# the ATT&CK release. Matched against the file head so we never parse the whole
# multi-MB bundle twice just to read one field.
COLLECTION_VERSION = re.compile(r'"x_mitre_version"\s*:\s*"([\d.]+)"')
D3FEND_FILE = "d3fend.json"
NIST_FILE = "nist-sp800-53-rev5.json"

ATTACK_ID = re.compile(r"T\d{4}(?:\.\d{3})?")
D3FEND_ID = re.compile(r"D3-[A-Z0-9]+")
NIST_ID = re.compile(r"[A-Za-z]{2}-\d+(?:\.\d+|\(\d+\))?")

REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# Markdown table parsing
# --------------------------------------------------------------------------- #
def iter_tables(path: Path):
    """Yield (header_cells, [(lineno, row_cells), ...]) for each pipe table."""
    header = None
    rows: list[tuple[int, list[str]]] = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.strip()
        if line.startswith("|") and line.endswith("|"):
            cells = [c.strip() for c in line.strip("|").split("|")]
            if header is None:
                header = cells
            elif set("".join(cells)) <= set("-: "):
                continue  # separator row
            else:
                rows.append((lineno, cells))
        else:
            if header is not None:
                yield header, rows
            header, rows = None, []
    if header is not None:
        yield header, rows


def column(header: list[str], name: str) -> int | None:
    return header.index(name) if name in header else None


def normalize_nist(token: str) -> str:
    """SC-28 -> sc-28 ; SC-7(3) -> sc-7.3 ; SC-7.3 -> sc-7.3."""
    return token.lower().replace("(", ".").replace(")", "")


def extract_ids(path: Path) -> dict[str, list[tuple[int, str]]]:
    """Return {framework: [(lineno, id), ...]} for one fiche.

    Also returns ``"covered"``: the set of ATT&CK IDs that appear in a cadres-table
    row carrying at least one defensive framework mapping (D3FEND or NIST). A
    technique cited by the fiche but absent from this set is defended by no
    recognized control (see the coverage check in :func:`main`).
    """
    found: dict[str, list[tuple[int, str]]] = {"attack": [], "d3fend": [], "nist": []}
    covered: set[str] = set()
    for header, rows in iter_tables(path):
        # First table: IDs live in the "ID" column (the "Technique ATT&CK" column
        # holds the technique *name*). Cadres table: IDs live in the
        # "Technique ATT&CK" column itself (no "ID" column present).
        if "Technique ATT&CK" in header and "ID" in header:
            att_col = column(header, "ID")
        elif "Technique ATT&CK" in header:
            att_col = column(header, "Technique ATT&CK")
        else:
            att_col = None
        d3_col = column(header, "D3FEND")
        nist_col = column(header, "NIST 800-53")
        for lineno, cells in rows:
            row_attack = (
                ATTACK_ID.findall(cells[att_col])
                if att_col is not None and att_col < len(cells)
                else []
            )
            found["attack"] += [(lineno, m) for m in row_attack]
            if d3_col is not None or nist_col is not None:
                d3 = cells[d3_col] if d3_col is not None and d3_col < len(cells) else ""
                nist = cells[nist_col] if nist_col is not None and nist_col < len(cells) else ""
                d3_ids = D3FEND_ID.findall(d3)
                nist_ids = NIST_ID.findall(nist)
                found["d3fend"] += [(lineno, m) for m in d3_ids]
                found["nist"] += [(lineno, normalize_nist(m)) for m in nist_ids]
                if not d3_ids and not nist_ids:
                    found.setdefault("gap", []).append((lineno, cells[0][:40]))
                else:
                    # This cadres row anchors its technique(s) to a real control:
                    # every ATT&CK ID it names is now defensively covered.
                    covered.update(row_attack)
    found["covered"] = sorted(covered)  # type: ignore[assignment]
    return found


# --------------------------------------------------------------------------- #
# Knowledge-base loaders
# --------------------------------------------------------------------------- #
def attack_external_id(obj) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") in MITRE_SOURCES:
            return ref.get("external_id")
    return None


def bundle_version(bundle: Path) -> str | None:
    """Return the ATT&CK release (x-mitre-collection x_mitre_version) of a bundle."""
    with bundle.open(encoding="utf-8") as fh:
        head = fh.read(4096)  # the collection object leads the bundle
    m = COLLECTION_VERSION.search(head)
    return m.group(1) if m else None


def load_attack_ids(data_dir: Path) -> tuple[set[str], set[str]]:
    try:
        from mitreattack.stix20 import MitreAttackData
    except ImportError:
        sys.exit("error: mitreattack-python not installed (pip install -r tools/requirements.txt)")
    bundles = [data_dir / n for n in STIX_FILES if (data_dir / n).is_file()]
    if not bundles:
        sys.exit(f"error: no ATT&CK STIX bundle in {data_dir}; see tools/README.md")
    valid: set[str] = set()
    deprecated: set[str] = set()
    for bundle in bundles:
        ver = bundle_version(bundle)
        if ver != ATTACK_VERSION:
            sys.exit(
                f"error: {bundle.name} is ATT&CK v{ver or '?'}, expected pinned "
                f"v{ATTACK_VERSION}; re-fetch the v{ATTACK_VERSION} bundle (see tools/README.md)"
            )
        data = MitreAttackData(str(bundle))
        for tech in data.get_techniques(remove_revoked_deprecated=False):
            ext_id = attack_external_id(tech)
            if not ext_id:
                continue
            (deprecated if tech.get("x_mitre_deprecated") or tech.get("revoked") else valid).add(ext_id)
    return valid, deprecated - valid


def load_d3fend_ids(data_dir: Path) -> set[str]:
    path = data_dir / D3FEND_FILE
    if not path.is_file():
        sys.exit(f"error: {D3FEND_FILE} not found in {data_dir}; see tools/README.md")
    ids: set[str] = set()

    def walk(o):
        if isinstance(o, dict):
            for k, v in o.items():
                if k == "d3f:d3fend-id" and isinstance(v, str):
                    ids.add(v)
                else:
                    walk(v)
        elif isinstance(o, list):
            for x in o:
                walk(x)

    walk(json.loads(path.read_text(encoding="utf-8")))
    return {i for i in ids if D3FEND_ID.fullmatch(i)}


def load_nist_ids(data_dir: Path) -> set[str]:
    path = data_dir / NIST_FILE
    if not path.is_file():
        sys.exit(f"error: {NIST_FILE} not found in {data_dir}; see tools/README.md")
    ids: set[str] = set()

    def rec(controls):
        for ctrl in controls:
            ids.add(ctrl["id"])
            rec(ctrl.get("controls", []))

    catalog = json.loads(path.read_text(encoding="utf-8"))["catalog"]
    for group in catalog.get("groups", []):
        rec(group.get("controls", []))
    return ids


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #
def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--security-dir", type=Path, default=REPO_ROOT / "security")
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=Path(os.environ.get("FRAMEWORK_DATA_DIR", REPO_ROOT / "tools" / ".frameworks")),
        help="directory holding the framework datasets",
    )
    args = parser.parse_args()

    fiches = sorted(args.security_dir.glob("*/README.md"))
    extra = args.security_dir / "frameworks.md"
    if extra.is_file():
        fiches.append(extra)
    if not fiches:
        sys.exit(f"error: no threat sheets under {args.security_dir}")

    attack_valid, attack_deprecated = load_attack_ids(args.data_dir)
    d3fend_valid = load_d3fend_ids(args.data_dir)
    nist_valid = load_nist_ids(args.data_dir)

    errors: list[str] = []
    warnings: list[str] = []
    counts = {"attack": 0, "d3fend": 0, "nist": 0}
    for fiche in fiches:
        rel = fiche.relative_to(REPO_ROOT)
        ids = extract_ids(fiche)
        for lineno, tid in ids["attack"]:
            counts["attack"] += 1
            if tid in attack_valid:
                continue
            if tid in attack_deprecated:
                warnings.append(f"{rel}:{lineno}: {tid} is deprecated/revoked upstream")
            else:
                errors.append(f"{rel}:{lineno}: unknown ATT&CK ID {tid}")
        for lineno, did in ids["d3fend"]:
            counts["d3fend"] += 1
            if did not in d3fend_valid:
                errors.append(f"{rel}:{lineno}: unknown D3FEND ID {did}")
        for lineno, nid in ids["nist"]:
            counts["nist"] += 1
            if nid not in nist_valid:
                errors.append(f"{rel}:{lineno}: unknown NIST 800-53 control {nid.upper()}")
        for lineno, label in ids.get("gap", []):
            warnings.append(f"{rel}:{lineno}: no framework mapping for “{label}…”")
        # Coverage: every ATT&CK technique cited must be countered by at least one
        # defensive control (D3FEND or NIST) in the cadres table. A technique with
        # no such mapping is an undefended threat — a hard error.
        covered = set(ids.get("covered", []))
        first_seen: dict[str, int] = {}
        for lineno, tid in ids["attack"]:
            first_seen.setdefault(tid, lineno)
        for tid in sorted(set(first_seen) - covered):
            errors.append(
                f"{rel}:{first_seen[tid]}: ATT&CK {tid} is covered by no defense "
                f"(no D3FEND/NIST mapping in the cadres table)"
            )

    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"error: {e}")

    print(
        f"\nchecked {counts['attack']} ATT&CK, {counts['d3fend']} D3FEND, "
        f"{counts['nist']} NIST refs across {len(fiches)} sheets: "
        f"{len(errors)} unknown, {len(warnings)} warnings"
    )
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
