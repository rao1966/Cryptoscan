
#!/usr/bin/env python3
"""
cryptoscan L1: certificate and key discovery (read-only, offline).

Walks a folder, finds X.509 certificates and public/private keys
(PEM or DER), and reports algorithm, key size, expiry and a simple
quantum-vulnerability flag. Output: console table + JSON file.

Usage:
    python scan_1.py /path/to/exported/files -o findings.json

Prototype only. The JSON is CBOM-like; verify field names against the
current CycloneDX CBOM specification before claiming compliance.
"""
import argparse
import json
import os
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import (
    dsa, ec, ed448, ed25519, rsa,
)

CERT_EXT = {".pem", ".crt", ".cer", ".der", ".key", ".pub", ".csr"}
MAX_SIZE = 5 * 1024 * 1024  # skip files larger than 5 MB

def describe_key(key):
    """Return (algorithm, key_size, quantum_vulnerable, note)."""
    if isinstance(key, rsa.RSAPublicKey) or isinstance(key, rsa.RSAPrivateKey):
        size = key.key_size
        note = "weak classical strength" if size < 2048 else ""
        return "RSA", size, True, note
    if isinstance(key, ec.EllipticCurvePublicKey) or isinstance(
            key, ec.EllipticCurvePrivateKey):
        return "ECDSA/ECDH-" + key.curve.name, key.curve.key_size, True, ""
    if isinstance(key, dsa.DSAPublicKey) or isinstance(key, dsa.DSAPrivateKey):
        return "DSA", key.key_size, True, "deprecated algorithm"
    if isinstance(key, (ed25519.Ed25519PublicKey, ed25519.Ed25519PrivateKey)):
        return "Ed25519", 256, True, ""
    if isinstance(key, (ed448.Ed448PublicKey, ed448.Ed448PrivateKey)):
        return "Ed448", 448, True, ""
    return type(key).__name__, None, None, "unrecognized key type"

def load_certs(data):
    """Yield certificates found in data (PEM bundle or single DER)."""
    found = []
    if b"-----BEGIN CERTIFICATE-----" in data:
        for cert in x509.load_pem_x509_certificates(data):
            found.append(cert)
    else:
        try:
            found.append(x509.load_der_x509_certificate(data))
        except ValueError:
            pass
    return found

def load_keys(data):
    """Return list of (kind, key) for PEM/DER keys without passwords."""
    keys = []
    if b"-----BEGIN" in data:
        blocks = data.split(b"-----BEGIN ")[1:]
        for b in blocks:
            pem = b"-----BEGIN " + b
            if b"CERTIFICATE" in pem.split(b"\n", 1)[0]:
                continue
            if b"ENCRYPTED" in pem.split(b"\n", 1)[0]:
                keys.append(("encrypted-private-key", None))
                continue
            for kind, loader in (
                ("private-key", lambda d: serialization.load_pem_private_key(d, None)),
                ("public-key", serialization.load_pem_public_key),
            ):
                try:
                    keys.append((kind, loader(pem)))
                    break
                except (ValueError, TypeError):
                    continue
    else:
        for kind, loader in (
            ("private-key", lambda d: serialization.load_der_private_key(d, None)),
            ("public-key", serialization.load_der_public_key),
        ):
            try:
                keys.append((kind, loader(data)))
                break
            except (ValueError, TypeError):
                continue
    return keys

def scan_file(path):
    results = []
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return [{"location": path, "error": str(e)}]

    for cert in load_certs(data):
        pub = cert.public_key()
        algo, size, qv, note = describe_key(pub)
        try:
            sig = cert.signature_algorithm_oid._name
        except Exception:
            sig = "unknown"
        expiry = cert.not_valid_after_utc
        expired = expiry < datetime.now(timezone.utc)
        results.append({
            "type": "certificate",
            "location": path,
            "subject": cert.subject.rfc4514_string(),
            "algorithm": algo,
            "key_size": size,
            "signature_algorithm": sig,
            "not_valid_after": expiry.isoformat(),
            "expired": expired,
            "quantum_vulnerable": qv,
            "note": note,
            "evidence_layer": "L1",
        })
    for kind, key in load_keys(data):
        if key is None:
            results.append({
                "type": kind, "location": path, "algorithm": "unknown",
                "key_size": None, "quantum_vulnerable": None,
                "note": "password-protected; cannot inspect",
                "evidence_layer": "L1",
            })
            continue
        algo, size, qv, note = describe_key(key)
        results.append({
            "type": kind, "location": path, "algorithm": algo,
            "key_size": size, "quantum_vulnerable": qv, "note": note,
            "evidence_layer": "L1",
        })
    return results

def walk(root):
    for dirpath, _, files in os.walk(root):
        for name in files:
            path = os.path.join(dirpath, name)
            ext = os.path.splitext(name)[1].lower()
            try:
                if os.path.getsize(path) > MAX_SIZE:
                    continue
            except OSError:
                continue
            if ext in CERT_EXT or ext == "":
                yield path

def to_cbom_like(findings):
    comps = []
    for i, f in enumerate(findings):
        if "error" in f:
            continue
        comps.append({
            "type": "cryptographic-asset",
            "bom-ref": f"asset-{i}",
            "name": f"{f['algorithm']}-{f['key_size']}",
            "evidence": {"occurrences": [{"location": f["location"]}]},
            "properties": [
                {"name": "asset-kind", "value": f["type"]},
                {"name": "quantum-vulnerable", "value": str(f["quantum_vulnerable"])},
                {"name": "evidence-layer", "value": f["evidence_layer"]},
            ],
        })
    return {"bomFormat": "CryptoScan-Prototype", "components": comps}

def main():
    ap = argparse.ArgumentParser(description="L1 certificate/key scanner")
    ap.add_argument("folder")
    ap.add_argument("-o", "--output", default="findings.json")
    args = ap.parse_args()

    if not os.path.isdir(args.folder):
        sys.exit(f"Not a folder: {args.folder}")

    findings = []
    for p in walk(args.folder):
        findings.extend(scan_file(p))

    print(f"{'TYPE':<22}{'ALGORITHM':<26}{'SIZE':<7}{'QVULN':<7}LOCATION")

    for f in findings:
        if "error" in f:
            continue
        print(f"{f['type']:<22}{f['algorithm']:<26}{str(f['key_size']):<7}"
              f"{str(f['quantum_vulnerable']):<7}{f['location']}")

    print(f"\n{len(findings)} item(s) found.")

    with open(args.output, "w") as out:
        json.dump(
            {"findings": findings, "cbom_like": to_cbom_like(findings)},
            out,
            indent=2
        )

    print(f"Wrote {args.output}")

if __name__ == "__main__":
    main()
