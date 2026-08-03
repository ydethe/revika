# tools/

Repo tooling that is **not** part of the Go module (`revika` stays cgo-free / pure
Go). These are standalone helpers, kept out of `go build ./...`.

## `check_attack_ids.py` — validate ATT&CK IDs in the threat model

Each threat sheet under `security/<ID>/README.md` maps the threat to MITRE ATT&CK
techniques in a table:

```
| Technique ATT&CK | ID | Application à ce scénario | Mesure de défense |
| --- | --- | --- | --- |
| Adversary-in-the-Middle | T1557 | ... | ... |
```

This script extracts every value in the `ID` column and checks it against the
official ATT&CK knowledge base (Enterprise + Mobile + ICS) loaded via
[`mitreattack-python`](https://github.com/mitre-attack/mitreattack-python):

- **unknown ID** (no matrix knows it) → error, exit code `1`;
- **deprecated/revoked ID** (still real, superseded upstream) → warning, exit `0`.

The CI job `.github/workflows/attack-ids.yml` runs it on any change under
`security/` or to this tool.

### Run locally

```bash
pip install -r tools/requirements.txt

# Fetch the STIX bundles once (any subset works; enterprise covers all current IDs).
mkdir -p tools/.attack-stix
base=https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master
for m in enterprise mobile ics; do
  curl -fsSL "$base/$m-attack/$m-attack.json" -o "tools/.attack-stix/$m-attack.json"
done

python tools/check_attack_ids.py
```

`tools/.attack-stix/` is a local cache of the downloaded bundles — git-ignored,
safe to delete. Override its location with `--stix-dir` or `$ATTACK_STIX_DIR`.
