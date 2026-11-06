#!/usr/bin/env python3
"""
cryptoscan L6: human knowledge layer.

Turns a filled interview/questionnaire CSV into (a) findings the
reconciler can merge and (b) a per-system context file (data lifetime and
exposure) that drives the risk score. It also lists WHO holds knowledge,
so retiring-expert risk is visible (link to the legacy-knowledge problem).

Usage:
    python scan_l6.py --make-template templates/l6_questionnaire.csv
    python scan_l6.py answers.csv -o findings_l6.json --context-out context_l6.json

CSV columns (see template):
  system, owner, asset, algorithm_family, key_size, purpose,
  data_lifetime_years, exposure, who_knows, notes
algorithm_family: RSA, EC, DH, DSA, AES, 3DES, DES, RC4, MD5, SHA1, SHA256,
                  PQC, unknown
exposure: isolated | internal | partner | internet  (or a number 1-5)

Human answers are evidence, not truth: confidence is recorded as
"stated by person" and should be corroborated by L1-L5 where possible.
"""
import argparse
import csv
import json
import sys
from collections import defaultdict

COLUMNS = ["system", "owner", "asset", "algorithm_family", "key_size",
           "purpose", "data_lifetime_years", "exposure", "who_knows", "notes"]
EXAMPLE = ["web1", "Payments team", "Customer portal TLS", "RSA", "2048",
           "transit", "10", "internet", "Senior system administrator (retiring 2027)",
           "cert renewed yearly by hand"]

FAMILY = {"RSA": ("RSA", False, True), "EC": ("EC", False, True),
          "ECDSA": ("EC", False, True), "ECDH": ("EC", False, True),
          "DH": ("DH", False, True), "DSA": ("DSA", False, True),
          "AES": ("symmetric", False, False),
          "3DES": ("legacy-primitive", True, False),
          "DES": ("legacy-primitive", True, False),
          "RC4": ("legacy-primitive", True, False),
          "MD5": ("legacy-primitive", True, False),
          "SHA1": ("legacy-primitive", True, False),
          "SHA256": ("hash", False, False), "PQC": ("pqc", False, False),
          "UNKNOWN": ("unknown", False, False)}
EXPOSURE = {"isolated": 1, "internal": 2, "partner": 3, "internet": 5}


def life_score(years):
    if years is None:
        return None
    return 1 if years <= 1 else 2 if years <= 5 else 3 if years <= 10 \
        else 4 if years <= 25 else 5


def expo_score(v):
    v = (v or "").strip().lower()
    if v in EXPOSURE:
        return EXPOSURE[v]
    try:
        return max(1, min(5, int(v)))
    except ValueError:
        return None


def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def main():
    ap = argparse.ArgumentParser(description="L6 questionnaire ingester")
    ap.add_argument("csv", nargs="?")
    ap.add_argument("--make-template")
    ap.add_argument("-o", "--output", default="findings_l6.json")
    ap.add_argument("--context-out", default="context_l6.json")
    a = ap.parse_args()

    if a.make_template:
        with open(a.make_template, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(COLUMNS)
            w.writerow(EXAMPLE)
        print(f"Wrote template {a.make_template}")
        return
    if not a.csv:
        sys.exit("Give a CSV file, or --make-template PATH")

    findings, ctx = [], defaultdict(dict)
    people = defaultdict(set)
    with open(a.csv, newline="", encoding="utf-8-sig") as f:
        for n, row in enumerate(csv.DictReader(f), 2):
            system = (row.get("system") or "").strip()
            if not system:
                continue
            fam_in = (row.get("algorithm_family") or "unknown").strip().upper()
            fam, weak, qv = FAMILY.get(fam_in, FAMILY["UNKNOWN"])
            size = num(row.get("key_size"))
            if fam == "RSA" and size and size < 2048:
                weak = True
            years = num(row.get("data_lifetime_years"))
            life, expo = life_score(years), expo_score(row.get("exposure"))
            if life:
                ctx[system]["lifetime"] = max(ctx[system].get("lifetime", 0), life)
            if expo:
                ctx[system]["exposure"] = max(ctx[system].get("exposure", 0), expo)
            who = (row.get("who_knows") or "").strip()
            if who:
                people[system].add(who)
            findings.append({
                "type": "interview", "layer": "L6", "system": system,
                "location": f"{a.csv}:{n}",
                "item": f"{fam_in} {int(size) if size else ''} "
                        f"({(row.get('asset') or '').strip()})".replace("  ", " "),
                "family": fam, "classical_weak": weak, "quantum_vulnerable": qv,
                "purpose": (row.get("purpose") or "").strip(),
                "owner": (row.get("owner") or "").strip(),
                "note": "stated by person; corroborate with L1-L5. "
                        + (row.get("notes") or "").strip(),
            })
    with open(a.output, "w") as fh:
        json.dump({"findings": findings,
                   "knowledge_holders": {k: sorted(v) for k, v in people.items()}},
                  fh, indent=2)
    with open(a.context_out, "w") as fh:
        json.dump(ctx, fh, indent=2)
    print(f"{len(findings)} interview finding(s); context for "
          f"{len(ctx)} system(s).")
    print("Knowledge holders (single points of failure to record):")
    for s, p in people.items():
        print(f"  {s}: {', '.join(sorted(p))}")
    print(f"Wrote {a.output} and {a.context_out}")


if __name__ == "__main__":
    main()
