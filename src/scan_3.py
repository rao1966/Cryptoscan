#!/usr/bin/env python3
"""
cryptoscan L3: job / script / source-snippet scanner (read-only, offline).

Searches batch jobs and scripts (shell, JCL, COBOL, REXX, bat/PowerShell,
cron, SQL, Java/Python snippets) for calls to encryption tools and crypto
APIs, including IBM ICSF/CCA callable service names.

Usage:
    python scan_l3.py /path/to/exported/jobs -o findings_l3.json

Prototype only. Rule tables are starting points: extend them and verify
ICSF service names against IBM documentation. Where the algorithm cannot
be known from the call alone (e.g. ICSF symmetric services, whose
algorithm depends on the key token) the finding is marked needs_review.
"""
import argparse
import json
import os
import re
import sys

COBOL_EXT = {".cob", ".cbl", ".cpy", ".cobol"}
TEXT_EXT = {".sh", ".bash", ".ksh", ".csh", ".zsh", ".bat", ".cmd", ".ps1",
            ".jcl", ".proc", ".prc", ".rexx", ".rex", ".pl", ".py", ".rb",
            ".php", ".java", ".sql", ".cron", ".txt", ".cfg", ".ctl",
            ".job", ""} | COBOL_EXT
MAX_SIZE = 2 * 1024 * 1024


def rec(label, family, weak=False, qvuln=False, note="", review=False):
    return {"item": label, "family": family, "classical_weak": weak,
            "quantum_vulnerable": qvuln, "note": note, "needs_review": review}


def _bits(m, i):
    try:
        return int(m.group(i)) if m.group(i) else None
    except (IndexError, ValueError):
        return None


def r_genrsa(m):
    b = _bits(m, 1)
    return [rec(f"openssl genrsa {b or 'default'}", "RSA",
                weak=bool(b and b < 2048), qvuln=True,
                note="" if b else "key size not stated; verify")]


def r_genpkey(m):
    b = _bits(m, 1)
    return [rec(f"openssl genpkey RSA {b or 'default'}", "RSA",
                weak=bool(b and b < 2048), qvuln=True)]


def r_ssh_keygen(m):
    alg = m.group(1).lower()
    b = _bits(m, 2)
    fam = {"rsa": "RSA", "dsa": "DSA", "ecdsa": "EC", "ed25519": "EC"}[alg]
    weak = alg == "dsa" or (alg == "rsa" and bool(b and b < 2048))
    return [rec(f"ssh-keygen {alg} {b or ''}".strip(), fam, weak=weak,
                qvuln=True)]


def r_enc(m):
    c = m.group(1).lower()
    if c.startswith(("des", "rc4", "rc2", "bf")):
        return [rec(f"openssl enc -{c}", "legacy-primitive", weak=True,
                    note="deprecated/broken cipher")]
    return [rec(f"openssl enc -{c}", "symmetric",
                note="symmetric: Grover halves effective strength; "
                     "review for long-lived data")]


def r_tls_opt(m):
    return [rec(f"TLS option -{m.group(1)}", "protocol", weak=True,
                note="deprecated protocol forced in script")]


def r_curl(m):
    return [rec(f"curl {m.group(1)}", "protocol", weak=True,
                note="deprecated protocol forced in script")]


def r_digest(m):
    n = (m.group(1) or m.group(2)).lower()
    return [rec(n, "legacy-primitive", weak=True,
                note="broken/deprecated hash (ok only for non-security "
                     "checksums)")]


def r_keytool(m):
    alg = (m.group(1) or "not stated").upper()
    b = _bits(m, 2)
    fam = {"RSA": "RSA", "DSA": "DSA", "EC": "EC"}.get(alg, "unknown-pubkey")
    weak = alg == "DSA" or (alg == "RSA" and bool(b and b < 2048))
    return [rec(f"keytool {alg} {b or ''}".strip(), fam, weak=weak,
                qvuln=True,
                note="" if m.group(1) else "-keyalg not stated; verify")]


def r_zip(m):
    return [rec("zip traditional encryption", "legacy-primitive", weak=True,
                note="ZipCrypto is weak")]


def r_gpg(m):
    return [rec("GnuPG/PGP", "unknown-pubkey", qvuln=True, review=True,
                note="key algorithm depends on keyring; confirm via L1/L6")]


ICSF_SYM = {"CSNBENC", "CSNBDEC", "CSNBSYE", "CSNBSYD"}
ICSF_PKA = {"CSNDDSG", "CSNDDSV", "CSNDPKE", "CSNDPKD", "CSNDPKG",
            "CSNDPKI"}
ICSF_HASH = {"CSNBOWH"}
ICSF_MAC = {"CSNBMGN", "CSNBMVR"}


def r_icsf(m):
    n = m.group(1).upper()
    if n in ICSF_SYM:
        return [rec(n, "symmetric", review=True,
                    note="ICSF symmetric service; DES/TDES vs AES depends "
                         "on key token: verify")]
    if n in ICSF_PKA:
        return [rec(n, "unknown-pubkey", qvuln=True, review=True,
                    note="ICSF PKA service (RSA/ECC); confirm key type")]
    if n in ICSF_HASH:
        return [rec(n, "hash", review=True, note="hash service; confirm "
                                                  "algorithm")]
    if n in ICSF_MAC:
        return [rec(n, "symmetric", review=True, note="MAC service")]
    return [rec(n, "unknown", review=True,
                note="ICSF/CCA service; classify manually")]


def r_jcipher(m):
    spec = m.group(1)
    u = spec.upper()
    if u.startswith(("DES", "RC4", "ARCFOUR", "RC2", "BLOWFISH")):
        return [rec(f"Cipher {spec}", "legacy-primitive", weak=True)]
    if u.startswith("RSA"):
        return [rec(f"Cipher {spec}", "RSA", qvuln=True)]
    if "/ECB/" in u:
        return [rec(f"Cipher {spec}", "symmetric", weak=True,
                    note="ECB mode leaks patterns")]
    return [rec(f"Cipher {spec}", "symmetric")]


def r_jdigest(m):
    return [rec(f"MessageDigest {m.group(1)}", "legacy-primitive",
                weak=True)]


def r_jkpg(m):
    a = m.group(1).upper()
    fam = {"RSA": "RSA", "DSA": "DSA", "EC": "EC"}.get(a, "DH")
    return [rec(f"KeyPairGenerator {a}", fam, weak=(a == "DSA"),
                qvuln=True)]


def r_pyhash(m):
    return [rec(f"hashlib.{m.group(1)}", "legacy-primitive", weak=True,
                note="ok only for non-security checksums")]


RULES = [(re.compile(p, re.I), fn) for p, fn in [
    (r"openssl\s+genrsa\b(?:.*?\b(\d{3,5})\b)?", r_genrsa),
    (r"openssl\s+genpkey\b.*?\bRSA\b(?:.*?rsa_keygen_bits:(\d+))?", r_genpkey),
    (r"ssh-keygen\b.*?-t\s+(rsa|dsa|ecdsa|ed25519)(?:.*?-b\s+(\d+))?",
     r_ssh_keygen),
    (r"openssl\s+enc\b.*?\s-(des-ede3\S*|des3\S*|des\S*|rc4\S*|rc2\S*|bf\S*"
     r"|aes-?\d+\S*|camellia\S*|chacha20\S*)", r_enc),
    (r"openssl\s+s_(?:client|server)\b.*?\s-(ssl2|ssl3|tls1_1|tls1)\b",
     r_tls_opt),
    (r"\bcurl\b.*?(--sslv[23]|--tlsv1\.[01])\b", r_curl),
    (r"\b(md5sum|sha1sum)\b|openssl\s+(?:dgst\s+-)?(md5|sha1)\b", r_digest),
    (r"keytool\b.*?-genkey(?:pair)?\b(?:.*?-keyalg\s+(\w+))?"
     r"(?:.*?-keysize\s+(\d+))?", r_keytool),
    (r"\bzip\b.*?\s-(?:e|P)\b", r_zip),
    (r"\bgpg2?\s+-", r_gpg),
    (r"\b(CSN[BDEF][A-Z0-9]{3,5})\b", r_icsf),
    (r"Cipher\.getInstance\(\s*\"([^\"]+)\"", r_jcipher),
    (r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", r_jdigest),
    (r"KeyPairGenerator\.getInstance\(\s*\"(RSA|DSA|EC|DH|DiffieHellman)\"",
     r_jkpg),
    (r"hashlib\.(md5|sha1)\(", r_pyhash),
]]


def is_comment(line, ext):
    s = line.strip()
    if not s:
        return True
    if s.startswith(("#", "//*", "--")) or s.upper().startswith("REM "):
        return True
    return ext in COBOL_EXT and len(line) > 6 and line[6] in "*/"


def scan_file(path):
    ext = os.path.splitext(path)[1].lower()
    try:
        with open(path, "rb") as f:
            raw = f.read()
    except OSError as e:
        return [{"location": path, "error": str(e)}]
    if b"\x00" in raw[:2048]:
        return []  # binary: L4's job
    out = []
    for no, line in enumerate(raw.decode("utf-8", "replace").splitlines(), 1):
        if is_comment(line, ext):
            continue
        for rx, fn in RULES:
            for m in rx.finditer(line):
                for r in fn(m):
                    r.update({"type": "job-call", "layer": "L3",
                              "location": f"{path}:{no}",
                              "evidence": line.strip()[:120]})
                    out.append(r)
    return out


def walk(root):
    for dp, _, files in os.walk(root):
        for n in files:
            p = os.path.join(dp, n)
            if os.path.splitext(n)[1].lower() in TEXT_EXT or \
                    n.lower() in ("crontab",):
                try:
                    if os.path.getsize(p) <= MAX_SIZE:
                        yield p
                except OSError:
                    pass


def main():
    ap = argparse.ArgumentParser(description="L3 job/script scanner")
    ap.add_argument("folder")
    ap.add_argument("-o", "--output", default="findings_l3.json")
    a = ap.parse_args()
    if not os.path.isdir(a.folder):
        sys.exit(f"Not a folder: {a.folder}")
    findings = []
    for p in walk(a.folder):
        findings.extend(scan_file(p))
    print(f"{'WEAK':<6}{'QVULN':<7}{'REVIEW':<8}{'ITEM':<34}LOCATION")
    for f in findings:
        if "error" in f:
            continue
        print(f"{str(f['classical_weak']):<6}{str(f['quantum_vulnerable']):<7}"
              f"{str(f['needs_review']):<8}{f['item'][:33]:<34}{f['location']}")
    print(f"\n{len(findings)} finding(s).")
    with open(a.output, "w") as fh:
        json.dump({"findings": findings}, fh, indent=2)
    print(f"Wrote {a.output}")


if __name__ == "__main__":
    main()
