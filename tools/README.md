# tools/

Repo tooling that is **not** part of the Go module (`revika` stays cgo-free / pure
Go). These are standalone helpers, kept out of `go build ./...`.

## `check_attack_ids.py` — validate framework IDs in the threat model

Each threat sheet under `security/<ID>/README.md` carries two tables. The first maps
the threat to MITRE ATT&CK techniques:

```
| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | ... | ... |
```

The second anchors each defense measure to recognized control frameworks
(vocabulary centralized in [`security/frameworks.md`](../security/frameworks.md)):

```
| Mesure de défense | D3FEND | NIST 800-53 |
| --- | --- | --- |
| Chiffrement client-side AES-256-GCM | D3-MENCR | SC-28 |
```

This script extracts every framework ID cited and checks it against the official
knowledge bases:

- **MITRE ATT&CK** (Enterprise + Mobile + ICS) via
  [`mitreattack-python`](https://github.com/mitre-attack/mitreattack-python) —
  unknown ID → error (exit `1`); deprecated/revoked ID → warning (exit `0`).
- **MITRE D3FEND** via the ontology JSON-LD — unknown `D3-XXXX` id → error.
- **NIST SP 800-53 Rev 5** via the OSCAL catalog — unknown control id → error.
  Enhancements accepted as `SC-7(3)` or `SC-7.3` (normalized to `sc-7.3`).

A row in the cadres table with `—` in *both* framework columns is a warning (the
measure maps to no framework — usually a deliberate P2P state-of-the-art gap).
`security/frameworks.md` is validated too, so no fiche can cite an ID it doesn't define.

It also enforces **defensive coverage**: every ATT&CK technique a fiche cites must be
countered by at least one control (D3FEND or NIST) in the cadres table. A technique
mapped only to `—`/`—` gap rows — or not mapped at all — is a hard error (exit `1`),
flagging an undefended threat in the model.

The CI job `.github/workflows/attack-ids.yml` runs it on any change under
`security/` or to this tool.

### Run locally

```bash
pip install -r tools/requirements.txt

mkdir -p tools/.frameworks
cd tools/.frameworks

# MITRE ATT&CK STIX bundles (any subset works; enterprise covers all current IDs).
base=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master
for m in enterprise mobile ics; do
  curl -fsSL "$base/$m-attack/$m-attack.json" -o "$m-attack.json"
done

# MITRE D3FEND ontology.
curl -fsSL https://d3fend.mitre.org/ontologies/d3fend.json -o d3fend.json

# NIST SP 800-53 Rev 5 OSCAL catalog.
curl -fsSL https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json \
  -o nist-sp800-53-rev5.json

cd ../..
python tools/check_attack_ids.py
```

`tools/.frameworks/` is a local cache of the downloaded datasets — git-ignored,
safe to delete. Override its location with `--data-dir` or `$FRAMEWORK_DATA_DIR`.
