#!/usr/bin/env python3
"""
cryptoscan L5: passive network observation from a capture file.

Reads a .pcap or .pcapng (that YOU are authorized to hold), reassembles
the start of each TCP flow, and extracts TLS handshake metadata:
  - negotiated version and cipher suite (ServerHello)
  - negotiated key-exchange group (TLS 1.3) incl. PQC hybrids
  - server certificate key/signature (visible only in TLS <= 1.2)
  - client offers of weak suites/protocols (ClientHello)

Usage:
    python scan_l5.py capture.pcap [--system-map map.json] -o findings_l5.json
    map.json example: {"10.0.0.5": "web1", "10.0.0.9": "batch1"}

Capture on an authorized network segment only, e.g.:
    tcpdump -i any -s 0 -w capture.pcap 'tcp port 443'

LIMITS: sees only traffic crossing the capture point; TLS 1.3 hides the
certificate; QUIC/UDP not parsed; no decryption is attempted. Name tables
are starting points: verify against the IANA TLS registries.
"""
import argparse
import json
import socket
import struct
import sys
from collections import defaultdict

SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000a: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA", 0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xc009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xc00a: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0x009e: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
}
GROUPS = {
    0x0017: "secp256r1", 0x0018: "secp384r1", 0x0019: "secp521r1",
    0x001d: "x25519", 0x001e: "x448", 0x0100: "ffdhe2048",
    0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
    0x11ec: "X25519MLKEM768", 0x11eb: "SecP256r1MLKEM768",
    0x6399: "X25519Kyber768Draft00",
    0x0200: "MLKEM512", 0x0201: "MLKEM768", 0x0202: "MLKEM1024",
}
PQC_GROUPS = {"X25519MLKEM768", "SecP256r1MLKEM768", "X25519Kyber768Draft00",
              "MLKEM512", "MLKEM768", "MLKEM1024"}
VERSIONS = {0x0300: "SSLv3", 0x0301: "TLS1.0", 0x0302: "TLS1.1",
            0x0303: "TLS1.2", 0x0304: "TLS1.3"}
WEAK_VERSIONS = {"SSLv3", "TLS1.0", "TLS1.1"}
WEAK_TOKENS = ("RC4", "3DES", "_DES_", "NULL", "EXPORT", "_MD5")


# ---------------------------------------------------------------- capture
def read_pcap(path):
    """Yield (linktype, packet_bytes) from pcap or pcapng."""
    with open(path, "rb") as f:
        data = f.read()
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        end = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
        link = struct.unpack(end + "I", data[20:24])[0]
        pos = 24
        while pos + 16 <= len(data):
            _, _, caplen, _ = struct.unpack(end + "IIII", data[pos:pos + 16])
            yield link, data[pos + 16:pos + 16 + caplen]
            pos += 16 + caplen
    elif magic == b"\x0a\x0d\x0d\x0a":
        links, pos = [], 0
        while pos + 12 <= len(data):
            btype, blen = struct.unpack("<II", data[pos:pos + 8])
            if blen < 12:
                break
            body = data[pos + 8:pos + blen - 4]
            if btype == 1:
                links.append(struct.unpack("<H", body[:2])[0])
            elif btype == 6:
                iface, _, _, caplen, _ = struct.unpack("<IIIII", body[:20])
                yield (links[iface] if iface < len(links) else 1), \
                    body[20:20 + caplen]
            pos += blen
    else:
        sys.exit("Unrecognized capture format (need pcap or pcapng)")


def l3_payload(link, pkt):
    if link == 1:
        et = struct.unpack(">H", pkt[12:14])[0]
        off = 14
        if et == 0x8100:
            et = struct.unpack(">H", pkt[16:18])[0]
            off = 18
    elif link == 113:
        et, off = struct.unpack(">H", pkt[14:16])[0], 16
    elif link == 276:
        et, off = struct.unpack(">H", pkt[0:2])[0], 20
    elif link == 0:
        et, off = 0x0800, 4
    elif link == 101:
        et, off = 0x0800, 0
    else:
        return None
    return et, pkt[off:]


def tcp_segments(path):
    flows = defaultdict(dict)
    for link, pkt in read_pcap(path):
        r = l3_payload(link, pkt)
        if not r:
            continue
        et, ip = r
        if et == 0x0800 and len(ip) >= 20 and ip[9] == 6:
            ihl = (ip[0] & 15) * 4
            src, dst = socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
            tcp = ip[ihl:struct.unpack(">H", ip[2:4])[0]]
        elif et == 0x86dd and len(ip) >= 40 and ip[6] == 6:
            src = socket.inet_ntop(socket.AF_INET6, ip[8:24])
            dst = socket.inet_ntop(socket.AF_INET6, ip[24:40])
            tcp = ip[40:40 + struct.unpack(">H", ip[4:6])[0]]
        else:
            continue
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        payload = tcp[(tcp[12] >> 4) * 4:]
        if payload:
            flows[(src, sport, dst, dport)].setdefault(seq, payload)
    for key, segs in flows.items():
        buf, nxt = b"", None
        for seq in sorted(segs):
            if nxt is not None and seq != nxt:
                break
            buf += segs[seq]
            nxt = seq + len(segs[seq])
            if len(buf) > 65536:
                break
        yield key, buf


# -------------------------------------------------------------------- TLS
def handshake_messages(buf):
    """Return list of (type, body) from plaintext handshake records."""
    hs, pos = b"", 0
    while pos + 5 <= len(buf) and buf[pos] in (20, 21, 22, 23):
        rtype, length = buf[pos], struct.unpack(">H", buf[pos + 3:pos + 5])[0]
        if rtype == 23:
            break
        if rtype == 22:
            hs += buf[pos + 5:pos + 5 + length]
        pos += 5 + length
    msgs, p = [], 0
    while p + 4 <= len(hs):
        n = int.from_bytes(hs[p + 1:p + 4], "big")
        msgs.append((hs[p], hs[p + 4:p + 4 + n]))
        p += 4 + n
    return msgs


def is_grease(v):
    return (v & 0x0f0f) == 0x0a0a and (v >> 8) == (v & 0xff)


def parse_exts(b, p):
    exts = {}
    if p + 2 > len(b):
        return exts
    end = p + 2 + struct.unpack(">H", b[p:p + 2])[0]
    p += 2
    while p + 4 <= min(end, len(b)):
        t, n = struct.unpack(">HH", b[p:p + 4])
        exts[t] = b[p + 4:p + 4 + n]
        p += 4 + n
    return exts


def parse_client_hello(b):
    p = 2 + 32
    p += 1 + b[p]
    n = struct.unpack(">H", b[p:p + 2])[0]
    suites = [struct.unpack(">H", b[p + 2 + i:p + 4 + i])[0]
              for i in range(0, n, 2)]
    p += 2 + n
    p += 1 + b[p]
    ex = parse_exts(b, p)
    vers, groups = [], []
    if 0x002b in ex:
        v = ex[0x002b]
        vers = [struct.unpack(">H", v[1 + i:3 + i])[0]
                for i in range(0, v[0], 2)]
    if 0x000a in ex:
        g = ex[0x000a]
        n = struct.unpack(">H", g[:2])[0]
        groups = [struct.unpack(">H", g[2 + i:4 + i])[0]
                  for i in range(0, n, 2)]
    return ([s for s in suites if not is_grease(s)],
            [v for v in vers if not is_grease(v)],
            [g for g in groups if not is_grease(g)])


def parse_server_hello(b):
    ver = struct.unpack(">H", b[:2])[0]
    p = 2 + 32
    p += 1 + b[p]
    suite = struct.unpack(">H", b[p:p + 2])[0]
    p += 3
    ex = parse_exts(b, p)
    if 0x002b in ex:
        ver = struct.unpack(">H", ex[0x002b][:2])[0]
    group = None
    if 0x0033 in ex and len(ex[0x0033]) >= 2:
        group = struct.unpack(">H", ex[0x0033][:2])[0]
    return ver, suite, group


def leaf_cert(b):
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import ec, rsa
        n = int.from_bytes(b[3:6], "big")
        cert = x509.load_der_x509_certificate(b[6:6 + n])
        k = cert.public_key()
        if isinstance(k, rsa.RSAPublicKey):
            return "RSA", k.key_size
        if isinstance(k, ec.EllipticCurvePublicKey):
            return "EC", k.curve.key_size
        return "other", None
    except Exception:
        return None


# ---------------------------------------------------------------- records
def rec(system, item, family, loc, weak=False, qv=False, note=""):
    return {"type": "network-observation", "layer": "L5", "system": system,
            "location": loc, "item": item, "family": family,
            "classical_weak": weak, "quantum_vulnerable": qv, "note": note}


def suite_records(system, loc, name, tls13_group):
    out = []
    weak = any(t in name for t in WEAK_TOKENS)
    out.append(rec(system, name, "legacy-primitive" if weak else "symmetric",
                   loc, weak=weak, note="negotiated cipher suite"))
    if name.startswith(("TLS_AES", "TLS_CHACHA")):
        return out
    body = name[4:]
    if body.startswith("ECDHE_"):
        out.append(rec(system, "ECDHE key exchange", "EC", loc, qv=True))
    elif body.startswith("DHE_"):
        out.append(rec(system, "DHE key exchange", "DH", loc, qv=True))
    elif body.startswith("RSA_"):
        out.append(rec(system, "static RSA key exchange", "RSA", loc, qv=True,
                       note="no forward secrecy: recorded traffic is "
                            "exposed to harvest-now-decrypt-later"))
    if "_ECDSA_" in name:
        out.append(rec(system, "ECDSA authentication", "EC", loc, qv=True))
    elif "_RSA_" in name and not body.startswith("RSA_"):
        out.append(rec(system, "RSA authentication", "RSA", loc, qv=True))
    return out


def analyze(path, sysmap):
    findings, seen = [], set()
    for (src, sp, dst, dp), buf in tcp_segments(path):
        if not buf or buf[0] != 22:
            continue
        for mtype, body in handshake_messages(buf):
            try:
                if mtype == 2:  # ServerHello: src is the server
                    system = sysmap.get(src, src)
                    loc = f"{src}:{sp}"
                    ver, suite, group = parse_server_hello(body)
                    v = VERSIONS.get(ver, hex(ver))
                    name = SUITES.get(suite, f"0x{suite:04x}")
                    key = ("S", loc, v, name, group)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(rec(system, f"negotiated {v}", "protocol",
                                        loc, weak=v in WEAK_VERSIONS))
                    findings += suite_records(system, loc, name, group)
                    if group is not None:
                        g = GROUPS.get(group, f"0x{group:04x}")
                        if g in PQC_GROUPS:
                            findings.append(rec(
                                system, f"key exchange group {g}", "pqc", loc,
                                note="post-quantum hybrid negotiated"))
                        else:
                            fam = "DH" if g.startswith("ffdhe") else "EC"
                            findings.append(rec(
                                system, f"key exchange group {g}", fam, loc,
                                qv=True, note="classical key exchange"))
                elif mtype == 11:  # Certificate (TLS <= 1.2 only)
                    r = leaf_cert(body)
                    if r and r[0] in ("RSA", "EC"):
                        system, loc = sysmap.get(src, src), f"{src}:{sp}"
                        findings.append(rec(
                            system, f"server certificate {r[0]}-{r[1]}", r[0],
                            loc, weak=(r[0] == "RSA" and r[1] < 2048),
                            qv=True, note="leaf cert seen on the wire"))
                elif mtype == 1:  # ClientHello: src is the client
                    suites, vers, groups = parse_client_hello(body)
                    system, loc = sysmap.get(src, src), f"{src}->{dst}:{dp}"
                    names = [SUITES.get(s, "") for s in suites]
                    bad = sorted({t for n in names for t in WEAK_TOKENS
                                  if t in n})
                    vn = {VERSIONS.get(v) for v in vers}
                    if bad or vn & WEAK_VERSIONS:
                        findings.append(rec(
                            system, "client offers weak options: " +
                            ", ".join(bad + sorted(vn & WEAK_VERSIONS)),
                            "legacy-primitive", loc, weak=True,
                            note="client-side configuration"))
                    gnames = {GROUPS.get(g) for g in groups}
                    if gnames & PQC_GROUPS:
                        findings.append(rec(
                            system, "client offers PQC hybrid group", "pqc",
                            loc, note=", ".join(sorted(gnames & PQC_GROUPS))))
            except (IndexError, struct.error):
                continue
    return findings


def main():
    ap = argparse.ArgumentParser(description="L5 passive TLS observer")
    ap.add_argument("pcap")
    ap.add_argument("--system-map")
    ap.add_argument("-o", "--output", default="findings_l5.json")
    a = ap.parse_args()
    sysmap = json.load(open(a.system_map)) if a.system_map else {}
    findings = analyze(a.pcap, sysmap)
    print(f"{'WEAK':<6}{'QVULN':<7}{'SYSTEM':<12}ITEM")
    for f in findings:
        print(f"{str(f['classical_weak']):<6}{str(f['quantum_vulnerable']):<7}"
              f"{f['system']:<12}{f['item']}")
    print(f"\n{len(findings)} observation(s).")
    with open(a.output, "w") as fh:
        json.dump({"findings": findings}, fh, indent=2)
    print(f"Wrote {a.output}")


if __name__ == "__main__":
    main()
