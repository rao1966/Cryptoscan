#!/usr/bin/env python3
"""
cryptoscan L4: binary / library signature scanner (read-only, offline).

Looks inside compiled files (executables, shared libraries, firmware,
jars) for evidence of cryptography when no source exists:
  - library version banners (OpenSSL, LibreSSL, wolfSSL, mbed TLS, ...)
  - crypto API / imported function names
  - algorithm constant tables (AES S-box, SHA-256 K, ...)
  - DER-encoded algorithm OIDs

Usage:
    python scan_l4.py /path/to/binaries -o findings_l4.json

IMPORTANT LIMITS (state these in your paper):
  - Presence of code or a constant table shows an implementation is
    PRESENT, not that it is USED.
  - Compilers often embed constants as instruction immediates, so a
    missing constant table proves nothing.
  - Packed, encrypted or obfuscated binaries defeat this layer.
Findings carry evidence_strength so the reconciler/reader can weigh them.
"""
import argparse
import json
import os
import re
import sys

MAX_SIZE = 50 * 1024 * 1024
BIN_EXT = {".so", ".dll", ".exe", ".bin", ".jar", ".class", ".elf", ".img",
           ".fw", ".o", ".a", ".dylib", ".sys", ".ocx", ".war"}
MAGICS = (b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe",
          b"PK\x03\x04")


def meta(family, weak=False, qvuln=False, note="", strength="medium"):
    return dict(family=family, classical_weak=weak, quantum_vulnerable=qvuln,
                note=note, evidence_strength=strength)


# --- string rules: regex (bytes) -> (label, meta) ------------------------
STRING_RULES = [
    (rb"OpenSSL\s+(\d+\.\d+\.\d+[a-z]?)", "OpenSSL banner",
     meta("library", note="check version against known-vulnerable/EOL "
                          "releases", strength="high")),
    (rb"LibreSSL\s+(\d+\.\d+\.\d+)", "LibreSSL banner",
     meta("library", strength="high")),
    (rb"wolfSSL\s+(?:Version\s+)?(\d+\.\d+\.\d+)", "wolfSSL banner",
     meta("library", strength="high")),
    (rb"mbed ?TLS\s+(\d+\.\d+\.\d+)", "mbed TLS banner",
     meta("library", strength="high")),
    (rb"\b(BoringSSL|GnuTLS|Bouncy ?Castle|NSS_3\.\d+)", "TLS/crypto library",
     meta("library", strength="medium")),
    (rb"\b(RSA_generate_key(?:_ex)?|RSA_public_encrypt|RSA_private_decrypt"
     rb"|RSA_sign|RSA_verify|EVP_PKEY_RSA|rsa_pkcs1_\w+)\b",
     "RSA API", meta("RSA", qvuln=True)),
    (rb"\b(EC_KEY_new\w*|ECDSA_sign|ECDSA_do_sign|ECDH_compute_key"
     rb"|EC_KEY_generate_key|EVP_PKEY_EC)\b",
     "EC API", meta("EC", qvuln=True)),
    (rb"\b(DH_generate_key|DH_compute_key|DH_generate_parameters\w*"
     rb"|DH_new)\b", "DH API", meta("DH", qvuln=True)),
    (rb"\b(DSA_sign|DSA_verify|DSA_generate_key|DSA_new)\b", "DSA API",
     meta("DSA", weak=True, qvuln=True, note="DSA is deprecated")),
    (rb"\b(DES_ecb_encrypt|DES_ncbc_encrypt|DES_set_key\w*|EVP_des_\w+"
     rb"|DES_crypt)\b", "DES/3DES API",
     meta("legacy-primitive", weak=True, note="deprecated cipher")),
    (rb"\b(EVP_rc4\w*|RC4_set_key|RC4\b)", "RC4 API",
     meta("legacy-primitive", weak=True, note="broken cipher")),
    (rb"\b(EVP_md5|MD5_Init|MD5_Update|MD5Init)\b", "MD5 API",
     meta("legacy-primitive", weak=True, note="broken hash")),
    (rb"\b(EVP_sha1|SHA1_Init|SHA1_Update|SHA1Init)\b", "SHA-1 API",
     meta("legacy-primitive", weak=True, note="deprecated for signatures")),
    (rb"\b(SSLv2_\w*method|SSLv3_\w*method|TLSv1_method|TLSv1_1_method)\b",
     "legacy TLS method", meta("protocol", weak=True,
                               note="deprecated protocol support")),
    (rb"\b(CryptGenKey|CryptAcquireContext\w*|BCryptGenerateKeyPair"
     rb"|BCryptSignHash|BCryptEncrypt)\b", "Windows crypto API",
     meta("unknown-pubkey", note="Windows CryptoAPI/CNG use; algorithm "
                                 "chosen at runtime: review")),
    (rb"\b(CALG_RC4|CALG_3DES\w*|CALG_DES|CALG_MD5|CALG_SHA1?)\b",
     "Windows legacy algorithm id",
     meta("legacy-primitive", weak=True)),
    (rb"(?i)\b(ml-?kem|mlkem|kyber|ml-?dsa|dilithium|sphincs|slh-?dsa)\b",
     "PQC algorithm name",
     meta("pqc", note="post-quantum algorithm referenced", strength="medium")),
]
STRING_RULES = [(re.compile(p), l, m) for p, l, m in STRING_RULES]

# --- byte-signature rules: (label, bytes, meta) -------------------------
BYTE_SIGS = [
    ("AES S-box table", bytes.fromhex("637c777bf26b6fc5"),
     meta("symmetric", note="AES implementation present", strength="low")),
    ("SHA-256 K table", bytes.fromhex("982f8a4291443771"),
     meta("hash", note="SHA-256 implementation present", strength="low")),
    ("MD5 T table", bytes.fromhex("78a46ad756b7c7e8"),
     meta("legacy-primitive", weak=True, note="MD5 implementation present",
          strength="low")),
    ("SHA-1 init constants",
     bytes.fromhex("0123456789abcdeffedcba9876543210f0e1d2c3"),
     meta("legacy-primitive", weak=True,
          note="SHA-1 implementation present", strength="low")),
    ("ChaCha20 constant", b"expand 32-byte k",
     meta("symmetric", note="ChaCha20 present", strength="medium")),
    ("OID rsaEncryption", bytes.fromhex("2a864886f70d010101"),
     meta("RSA", qvuln=True, note="RSA key/cert structure or parser",
          strength="medium")),
    ("OID id-ecPublicKey", bytes.fromhex("2a8648ce3d0201"),
     meta("EC", qvuln=True, strength="medium")),
    ("OID prime256v1", bytes.fromhex("2a8648ce3d030107"),
     meta("EC", qvuln=True, note="P-256", strength="medium")),
    ("OID secp384r1", bytes.fromhex("2b81040022"),
     meta("EC", qvuln=True, note="P-384", strength="medium")),
    ("OID Ed25519", bytes.fromhex("2b6570"),
     meta("EC", qvuln=True, note="Ed25519", strength="low")),
    ("OID id-dsa", bytes.fromhex("2a8648ce380401"),
     meta("DSA", weak=True, qvuln=True, strength="medium")),
    ("OID sha1WithRSA", bytes.fromhex("2a864886f70d010105"),
     meta("legacy-primitive", weak=True, note="SHA-1 RSA signatures",
          strength="medium")),
    ("OID md5WithRSA", bytes.fromhex("2a864886f70d010104"),
     meta("legacy-primitive", weak=True, note="MD5 RSA signatures",
          strength="medium")),
]


def looks_binary(path, head):
    if os.path.splitext(path)[1].lower() in BIN_EXT:
        return True
    return head.startswith(MAGICS) or b"\x00" in head[:4096]


def scan_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        return [{"location": path, "error": str(e)}]
    if not looks_binary(path, data[:4096]):
        return []
    out = []

    def add(label, m, count, extra=""):
        out.append({"type": "binary-evidence", "layer": "L4",
                    "location": path, "item": label + extra,
                    "count": count, **m})

    for rx, label, m in STRING_RULES:
        hits = rx.findall(data)
        if hits:
            names = sorted({(h if isinstance(h, bytes) else h[0])
                            .decode("ascii", "replace") for h in hits})[:4]
            add(label, m, len(hits), f" ({', '.join(names)})")
    for label, sig, m in BYTE_SIGS:
        c = data.count(sig)
        if c:
            add(label, m, c)
    return out


def walk(root):
    for dp, _, files in os.walk(root):
        for n in files:
            p = os.path.join(dp, n)
            try:
                if os.path.islink(p) or os.path.getsize(p) > MAX_SIZE:
                    continue
            except OSError:
                continue
            yield p


def main():
    ap = argparse.ArgumentParser(description="L4 binary signature scanner")
    ap.add_argument("folder")
    ap.add_argument("-o", "--output", default="findings_l4.json")
    a = ap.parse_args()
    if not os.path.isdir(a.folder):
        sys.exit(f"Not a folder: {a.folder}")
    findings = []
    for p in walk(a.folder):
        findings.extend(scan_file(p))
    print(f"{'STRENGTH':<10}{'WEAK':<6}{'QVULN':<7}{'ITEM':<44}LOCATION")
    for f in findings:
        if "error" in f:
            continue
        print(f"{f['evidence_strength']:<10}{str(f['classical_weak']):<6}"
              f"{str(f['quantum_vulnerable']):<7}{f['item'][:43]:<44}"
              f"{f['location']}")
    print(f"\n{len(findings)} finding(s). Presence is not proof of use.")
    with open(a.output, "w") as fh:
        json.dump({"findings": findings}, fh, indent=2)
    print(f"Wrote {a.output}")


if __name__ == "__main__":
    main()
