
#!/usr/bin/env python3
"""
CryptoScan L2: Cryptographic Configuration Scanner
Read-only and offline.

Scans exported configuration files for:
- Weak or deprecated TLS protocols and cipher settings
- Weak SSH algorithms and key-exchange settings
- RSA, DH and elliptic-curve quantum-vulnerable mechanisms
- Weak OpenSSL and Java security configuration

Prototype only. Findings require contextual validation.
"""

import argparse
import json
import os
import re
from datetime import datetime, timezone

EXTENSIONS = {
    ".conf", ".cnf", ".ini", ".cfg", ".properties",
    ".xml", ".txt", ".config"
}

MAX_SIZE = 5 * 1024 * 1024

# Classical weaknesses and quantum-vulnerable mechanisms.
RULES = [
    {
        "pattern": r"\bTLSv1(?:\.0)?\b|\bTLSv1\.1\b|\bSSLv[23]\b",
        "issue": "Deprecated TLS/SSL protocol",
        "severity": "HIGH",
        "quantum": False
    },
    {
        "pattern": r"\b(?:RC4|3DES|DES|MD5|NULL|EXPORT)\b",
        "issue": "Weak or deprecated cryptographic algorithm",
        "severity": "HIGH",
        "quantum": False
    },
    {
        "pattern": r"\b(?:RSA|DHE|DH|ECDHE|ECDH|ECDSA)\b",
        "issue": "Classical public-key mechanism potentially vulnerable to large-scale quantum attacks",
        "severity": "QUANTUM",
        "quantum": True
    },
    {
        "pattern": r"\bssh-rsa\b",
        "issue": "SSH RSA/SHA-1 signature algorithm",
        "severity": "HIGH",
        "quantum": True
    },
    {
        "pattern": r"\b(?:diffie-hellman-group1-sha1|diffie-hellman-group14-sha1)\b",
        "issue": "Weak SSH Diffie-Hellman configuration",
        "severity": "HIGH",
        "quantum": True
    },
    {
        "pattern": r"\b(?:aes128-cbc|aes256-cbc|3des-cbc)\b",
        "issue": "Legacy SSH cipher configuration",
        "severity": "MEDIUM",
        "quantum": False
    },
    {
        "pattern": r"\b(?:secp256r1|secp384r1|prime256v1|brainpoolP\d+)\b",
        "issue": "Elliptic-curve cryptographic mechanism",
        "severity": "QUANTUM",
        "quantum": True
    }
]

# Configuration directives worth examining.
DIRECTIVES = {
    "ssl_protocols",
    "ssl_ciphers",
    "ssl_ecdh_curve",
    "ssl_certificate",
    "ssl_certificate_key",
    "ssl_protocol",
    "ssl_cipher",
    "ssl_cipher_suite",
    "sslminimumprotocol",
    "sslminimumprotocolversion",
    "kexalgorithms",
    "hostkeyalgorithms",
    "pubkeyacceptedalgorithms",
    "ciphers",
    "cipher",
    "tlsenabledprotocols",
    "jdk.tls.disabledalgorithms",
    "jdk.certpath.disabledalgorithms",
    "securerandom.source",
    "group",
    "signature_algorithms",
    "sshd_config"
}


def scan_file(path):
    findings = []

    try:
        if os.path.getsize(path) > MAX_SIZE:
            return findings

        with open(path, "r", encoding="utf-8",
                  errors="replace") as f:
            lines = f.readlines()

    except (OSError, PermissionError) as e:
        return [{
            "location": path,
            "error": str(e),
            "evidence_layer": "L2"
        }]

    for line_number, line in enumerate(lines, 1):

        stripped = line.strip()

        if not stripped or stripped.startswith(("#", ";", "!")):
            continue

        # Remove inline comments.
        content = re.split(r"\s[;#]", stripped, maxsplit=1)[0]

        # Determine whether this is a recognized crypto directive.
        directive_match = re.match(
            r"^\s*([A-Za-z0-9_.-]+)\s*(?:=|\s+)",
            content
        )

        directive = (
            directive_match.group(1).lower()
            if directive_match else ""
        )

        for rule in RULES:
            match = re.search(
                rule["pattern"], content, re.IGNORECASE
            )

            if not match:
                continue

            findings.append({
                "type": "configuration-finding",
                "location": path,
                "line": line_number,
                "directive": directive or "unclassified",
                "matched_value": match.group(0),
                "issue": rule["issue"],
                "severity": rule["severity"],
                "quantum_vulnerable": rule["quantum"],
                "evidence": stripped[:500],
                "evidence_layer": "L2"
            })

    return findings


def walk(root):
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [
            d for d in dirs
            if d.lower() not in {
                ".git", "__pycache__", "node_modules"
            }
        ]

        for name in files:
            ext = os.path.splitext(name)[1].lower()

            if ext in EXTENSIONS or ext == "":
                yield os.path.join(dirpath, name)


def main():
    parser = argparse.ArgumentParser(
        description="CryptoScan L2 Configuration Scanner"
    )

    parser.add_argument("folder", help="Folder containing exported configurations")
    parser.add_argument(
        "-o", "--output",
        default="findings_l2.json",
        help="JSON output file"
    )

    args = parser.parse_args()

    if not os.path.isdir(args.folder):
        parser.error("Not a valid folder: " + args.folder)

    findings = []
    scanned = 0

    print("\nCryptoScan L2 - Configuration Scanner")
    print("=" * 100)

    for path in walk(args.folder):
        scanned += 1
        results = scan_file(path)
        findings.extend(results)

    print(
        f"\n{'SEVERITY':<12}{'QUANTUM':<10}"
        f"{'DIRECTIVE':<28}{'MATCH':<25}LOCATION"
    )
    print("-" * 100)

    for item in findings:
        if "error" in item:
            print("ERROR:", item["location"], item["error"])
            continue

        print(
            f"{item['severity']:<12}"
            f"{str(item['quantum_vulnerable']):<10}"
            f"{item['directive']:<28}"
            f"{item['matched_value']:<25}"
            f"{item['location']}:{item['line']}"
        )

    report = {
        "scanner": "CryptoScan L2",
        "evidence_layer": "L2",
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "scanned_folder": os.path.abspath(args.folder),
        "files_examined": scanned,
        "total_findings": len(findings),
        "findings": findings,
        "limitations": [
            "Pattern-based prototype; findings require manual validation.",
            "A quantum flag is not evidence of an actual quantum attack.",
            "Configuration context and effective runtime settings are not verified.",
            "No official CycloneDX CBOM compliance is claimed."
        ]
    }

    with open(args.output, "w", encoding="utf-8") as out:
        json.dump(report, out, indent=2)

    print("\n" + "=" * 100)
    print(f"Files examined : {scanned}")
    print(f"Findings       : {len(findings)}")
    print(f"JSON report    : {os.path.abspath(args.output)}")
    print("\nL2 scan completed.")


if __name__ == "__main__":
    main()

