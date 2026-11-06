#!/usr/bin/env python3
"""
cryptoscan reconciler: merges evidence from several layers into one
inventory, assigns confidence, raises cross-layer review flags, and
ranks risk.

Usage:
    python reconcile.py --l1 findings.json --l2 findings_l2.json \
        [--l3 f3.json] [--l4 f4.json] [--l5 f5.json] [--l6 f6.json] \
        [--context context.json] [--system-index 1] \
        [-o inventory.json] [--report report.md]

How systems are identified:
    Export each host/system into its own sub-folder, e.g.
        estate/web1/server.crt
        estate/web1/nginx.conf
    With the default --system-index 1, the system is the 2nd path
    component ("web1"). Use 0 if you scanned each host separately.

Optional context file (JSON), per system, scale 1-5:
    {"web1": {"lifetime": 5, "exposure": 5}}
    lifetime = how long protected data must stay secret
    exposure = how reachable it is (5 = public internet)
Unknown values default to 3 and the item is marked "context needed".

Prototype only. The risk model is a transparent starting point for
discussion, NOT a validated standard.
"""
import argparse
import json
import os
import sys
from collections import defaultdict

LABEL_FAMILY = {
    "RSA": "RSA", "ECDH/EC curve": "EC", "ECDSA/EdDSA": "EC", "DH": "DH",
    "SHA-1/DSA-era": "legacy-primitive", "DH-group1": "DH",
    "SSLv2": "protocol", "SSLv3": "protocol", "TLS1.0": "protocol",
    "TLS1.1": "protocol", "RC4": "legacy-primitive",
    "3DES": "legacy-primitive", "DES": "legacy-primitive",
    "EXPORT": "legacy-primitive", "NULL": "legacy-primitive",
    "MD5": "legacy-primitive",
}



def system_of(location, index):
    """Identify the scanned project/system from a Windows or POSIX path."""
    if not location:
        return "(unspecified)"

    path = str(location).replace("\\", "/")

    # Remove a trailing line number, if present.
    path = path.rsplit(":", 1)[0] if (
        ":" in path and path.rsplit(":", 1)[1].isdigit()
    ) else path

    # Relative paths belong to the current scanned project.
    if path.startswith("./") or not path.startswith("/"):
        return "C_era"

    parts = [p for p in path.split("/") if p]

    # Windows absolute path: C:/Users/name/Desktop/project/...
    if len(parts) >= 5 and parts[0].endswith(":"):
        return parts[4]

    # POSIX path: /home/user/project/...
    if len(parts) >= 3 and parts[0] == "home":
        return parts[2]

    return parts[index] if len(parts) > index else "(unspecified)"

def l1_family(algorithm):
    a = str(algorithm).upper()

    if a.startswith("RSA"):
        return "RSA"
    if a.startswith(("ED25519", "ED448")):
        return "EdDSA"
    if a.startswith("ECDSA"):
        return "EC"
    if a.startswith("DSA"):
        return "DSA"

    return "other"


def normalize_l1(findings, idx):
    out = []

    # Accept either a findings list or the complete JSON object.
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    for f in findings:
        if not isinstance(f, dict):
            continue
        if "error" in f or not f.get("algorithm"):
            continue
        fam = l1_family(f["algorithm"])
        size = f.get("key_size")
        weak = "weak" in str(f.get("note", "")).lower()
        if fam == "RSA" and size and size < 2048:
            weak = True
        out.append({
           "system": "C_era" if not os.path.isabs(f["location"]) else system_of(f["location"], idx), "family": fam,
            "item": f"{f['algorithm']}-{size}", "layer": "L1",
            "location": f["location"], "asset_type": f["type"],
            "classical_weak": weak,
            "quantum_vulnerable": bool(f.get("quantum_vulnerable")),
            "note": f.get("note", ""),
            "evidence": "Certificate subject: {}; Public-key algorithm: {}; Key size: {}; Signature algorithm: {}; Not valid after: {}; Expired: {}".format(f.get("subject", "unknown"), f.get("algorithm", "unknown"), size if size is not None else "unknown", f.get("signature_algorithm", "unknown"), f.get("not_valid_after", "unknown"), f.get("expired", "unknown")),
            "evidence_strength": "high",
        })
    return out



def normalize_l2(findings, idx):
    """Normalize CryptoScan L2 configuration findings."""
    out = []

    # Accept either a findings list or the complete JSON object.
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    for f in findings:
        if not isinstance(f, dict) or "error" in f:
            continue

        value = str(f.get("matched_value", "")).strip()
        if not value:
            continue

        value_upper = value.upper()
        issue = str(f.get("issue", ""))
        issue_lower = issue.lower()

        # Identify the cryptographic family.
        if value_upper.startswith("RSA"):
            family = "RSA"
        elif value_upper in (
            "PRIME256V1", "SECP256R1", "P-256",
            "ECDH", "ECDSA", "ECDH/EC CURVE"
        ):
            family = "EC"
        elif value_upper.startswith(("TLS", "SSL")):
            family = "protocol"
        else:
            family = LABEL_FAMILY.get(value_upper, "other")

        quantum = bool(f.get("quantum_vulnerable", False))

        # Explicitly identify weak or deprecated mechanisms.
        classical_weak = bool(f.get("classical_weak", False))

        location = f.get("location", "(unknown)")

        out.append({
            "system": system_of(location, idx),
            "family": family,
            "item": value,
            "layer": "L2",
            "location": location,
            "asset_type": "config-directive",
            "classical_weak": classical_weak,
            "quantum_vulnerable": quantum,
            "note": (
                f"{f.get('directive', 'configuration')}: "
                f"{issue}; severity={f.get('severity', 'unknown')}; "
                f"evidence={f.get('evidence', '')}"
            ),
            "evidence": f.get("evidence", ""),
            "evidence_strength": f.get("evidence_strength") or "medium",
            "needs_review": True
        })

    return out


def normalize_generic(findings, idx, layer):
    """Normalize L3-L6 findings while preserving evidence and review status."""
    out = []

    # Accept either a findings list or a complete JSON object.
    if isinstance(findings, dict):
        findings = findings.get("findings", [])

    for f in findings:
        if not isinstance(f, dict):
            continue

        if "error" in f or not f.get("family"):
            continue

        location = f.get("location", "")

        out.append({
            "system": f.get("system") or (
                "C_era" if not os.path.isabs(location)
                else system_of(location, idx)
            ),
            "family": f["family"],
            "item": f.get("item", "unspecified"),
            "layer": layer,
            "location": location,
            "asset_type": f.get("type", "finding"),
            "classical_weak": bool(f.get("classical_weak")),
            "quantum_vulnerable": bool(f.get("quantum_vulnerable")),
            "note": f.get("note", ""),
            "needs_review": bool(f.get("needs_review")),
                                    "evidence": f.get("evidence") or (
                "PCAP observation: " + str(f.get("item", "")) + "; endpoints: " + str(location) + "; client-offered options only; negotiation not established."
                if layer == "L5" else
                "Interview-reported: item=" + str(f.get("item", "")) + "; owner=" + str(f.get("owner", "unknown")) + "; purpose=" + str(f.get("purpose", "unknown")) + "; note=" + str(f.get("note", ""))
                if layer == "L6" else
                "Binary signature indicator: " + str(f.get("item", "")) + "; match count: " + str(f.get("count", "unknown")) + "; raw byte offset and runtime use not established."
                if layer == "L4" else ""
            ),
            "evidence_strength": f.get("evidence_strength") or (
                "medium" if layer in ("L3", "L5") else
                "low" if layer == "L6" else ""
            ),
        })

    return out


def vulnerability(members):
    if any(m["classical_weak"] for m in members):
        return 5
    if any(m["quantum_vulnerable"] for m in members):
        return 4
    if any(m.get("family") in ("unknown", "other") for m in members):
        return None
    return 1

def reconcile(records, context):
    groups = defaultdict(list)
    for r in records:
        groups[(r["system"], r["family"])].append(r)

    inventory = []
    for (system, family), members in groups.items():
        layers = sorted({m["layer"] for m in members})
        ctx = context.get(system, {})
        life, expo = ctx.get("lifetime"), ctx.get("exposure")

        for name, value in (("lifetime", life), ("exposure", expo)):
            if value is not None and (
                type(value) is not int or not 1 <= value <= 5
            ):
                raise ValueError(
                    f"Invalid {name} for system {system}: {value}. "
                    "Expected an integer from 1 to 5."
                )

        lifetime_missing = life is None
        exposure_missing = expo is None
        needs_ctx = lifetime_missing or exposure_missing
        life = 3 if lifetime_missing else life
        expo = 3 if exposure_missing else expo

        vuln = vulnerability(members)
        risk_score = vuln * life * expo if vuln is not None else None

        inventory.append({
            "system": system,
            "family": family,
            "items": sorted({m["item"] for m in members}),
            "layers": layers,
            "confidence": (
                "family-level corroboration (asset unconfirmed)"
                if len(layers) > 1 else "single-source"
            ),
            "vulnerability": vuln,
            "lifetime": life,
            "exposure": expo,
            "risk_score": risk_score,
            "risk_status": (
                "unclassified - assessment required"
                if risk_score is None else "provisional"
            ),
            "context_needed": needs_ctx,
            "lifetime_missing": lifetime_missing,
            "exposure_missing": exposure_missing,
            "members": members,
        })

    flags = []
    grouped_flags = {}

    for e in inventory:
        for m in e["members"]:
            if (
                m.get("needs_review")
                or m.get("classical_weak")
                or m.get("quantum_vulnerable")
            ):
                if m.get("classical_weak"):
                    reason = "Weak or deprecated cryptographic primitive."
                elif m.get("quantum_vulnerable"):
                    reason = (
                        "Quantum-vulnerable algorithm or mechanism; "
                        "assess migration to post-quantum cryptography."
                    )
                else:
                    reason = (
                        m.get("note")
                        or "Classification or usage is uncertain."
                    )

                flag_key = (
                    e["system"],
                    e["family"],
                    reason
                )

                grouped_flags.setdefault(flag_key, []).append(
                    m["item"]
                )

    for (system, family, reason), items in grouped_flags.items():
        unique_items = sorted(set(items))
        flag_text = (
            f"{', '.join(unique_items)} require review: {reason}"
        )

        flags.append({
            "system": system,
            "family": family,
            "flag": flag_text
        })
    by_system = defaultdict(dict)
    for e in inventory:
        by_system[e["system"]][e["family"]] = e

    for system, fams in by_system.items():
        for e in fams.values():
            if e["context_needed"]:
                if e["lifetime_missing"] and e["exposure_missing"]:
                    context_flag = "Lifetime and exposure context are missing; default assumptions were used."
                elif e["lifetime_missing"]:
                    context_flag = "Lifetime context is missing; a default assumption was used."
                else:
                    context_flag = "Exposure context is missing; a default assumption was used."
                flags.append({
                    "system": system,
                    "family": e["family"],
                    "flag": context_flag
                })

    inventory.sort(
        key=lambda e: (
            e["risk_score"] is None,
            -(e["risk_score"] or 0)
        )
    )

    return inventory, flags
def write_report(path, inventory, flags):
    """Write a Markdown report of the reconciled cryptographic inventory."""

    lines = [
        "# Cryptographic Inventory Report",
        "",
        "## Risk model",
        "",
        "Risk = Vulnerability x Lifetime x Exposure.",
        "Each factor uses an integer scale from 1 to 5.",
        "When lifetime or exposure context is missing, the prototype "
        "uses a default value of 3 for that factor and marks the "
        "finding as requiring context.",
        "These default assumptions are provisional and are not "
        "validated measurements.",
        "Scores are provisional and require contextual assessment.",
        "Unclassified findings are not assigned a risk score.",
        "",
        "## Inventory",
        "",
        "| System | Family | Layers | Risk | Status | Items |",
        "|---|---|---|---:|---|---|",
    ]

    for e in inventory:
        risk = (
            str(e["risk_score"])
            if e["risk_score"] is not None
            else "Unclassified"
        )
        items = ", ".join(e["items"]).replace("|", "\\|")
        layers = "+".join(e["layers"])

        lines.append(
            f"| {e['system']} | {e['family']} | {layers} | "
            f"{risk} | {e['risk_status']} | {items} |"
        )

    lines.extend([
        "",
        "## Review flags",
        "",
    ])

    if flags:
        for f in flags:
            lines.append(
                f"- **{f['system']} / {f['family']}**: {f['flag']}"
            )
    else:
        lines.append("No review flags.")

    lines.extend([
        "",
        "## Interpretation and limitations",
        "",
        "- Detection indicates evidence of cryptographic material or "
        "mechanisms, not necessarily active use.",
        "- Findings from different layers may corroborate a family "
        "without confirming that they belong to the same asset.",
        "- Missing lifetime or exposure context uses provisional "
        "default assumptions.",
        "- The default value of 3 is an assumption, not an "
        "empirically established measurement.",
        "- Network observations from synthetic test captures, "
        "including 192.0.2.10, represent test evidence and not "
        "confirmed production assets.",
        "- Unclassified findings require manual assessment; they "
        "must not be interpreted as low risk.",
        "",
    ])

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
def load(path):
    """Load JSON data from a file."""
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def main():
    ap = argparse.ArgumentParser(description="Reconcile layer findings")
    ap.add_argument("--l1")
    ap.add_argument("--l2")
    for n in ("l3", "l4", "l5", "l6"):
        ap.add_argument(f"--{n}")
    ap.add_argument("--context")
    ap.add_argument("--system-index", type=int, default=1)
    ap.add_argument("-o", "--output", default="inventory.json")
    ap.add_argument("--report", default="report.md")
    a = ap.parse_args()
    if not any(getattr(a, n) for n in ("l1", "l2", "l3", "l4", "l5", "l6")):
        sys.exit("Give at least one of --l1 ... --l6")

    records = []
    if a.l1:
        records += normalize_l1(load(a.l1), a.system_index)
    if a.l2:
        records += normalize_l2(load(a.l2), a.system_index)
    for n in ("l3", "l4", "l5", "l6"):
        if getattr(a, n):
            records += normalize_generic(load(getattr(a, n)), a.system_index,
                                         n.upper())
    context = {}
    if a.context:
        with open(a.context) as fh:
            context = json.load(fh)

    inventory, flags = reconcile(records, context)
    with open(a.output, "w") as fh:
        json.dump({"inventory": inventory, "review_flags": flags}, fh,
                  indent=2)
    write_report(a.report, inventory, flags)

    print(f"{'RISK':<6}{'SYSTEM':<12}{'FAMILY':<18}{'LAYERS':<8}ITEMS")
    
    for e in inventory:
        risk = str(e["risk_score"]) if e["risk_score"] is not None else "N/A"
        print(f"{risk:<6}{e['system']:<12}{e['family']:<18}"
              f"{'+'.join(e['layers']):<8} {', '.join(e['items'])}")
    print(f"\n{len(inventory)} inventory entries, {len(flags)} review flags.")
    print(f"Wrote {a.output} and {a.report}")


if __name__ == "__main__":
    main()
