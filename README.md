# CryptoScan
## A Source-Code-Independent Framework for Legacy Cryptographic Discovery

**Author:** Dr. Srinivasa Rao Angajala  
**Affiliation:** Independent Researcher, Guntur, Andhra Pradesh, India

**Research preprint:** [https://doi.org/10.5281/zenodo.23955931](https://doi.org/10.5281/zenodo.23955931)

---

## 1. Overview

CryptoScan is a research-oriented prototype exploring source-code-independent discovery of cryptographic artifacts in legacy and heterogeneous computing environments.

The project addresses an important challenge in the post-quantum era: organizations cannot effectively plan cryptographic migration without first identifying where cryptographic mechanisms are used.

CryptoScan proposes a layered approach to identifying cryptographic assets through certificates, keys, configuration files, binary artifacts, runtime observations and evidence correlation.

## 2. Proposed Six-Layer Architecture

| Layer | Description | Status |
|---|---|---|
| L1 | Certificate and Key Discovery | Implemented |
| L2 | Cryptographic Configuration Discovery | Implemented |
| L3 | Library, Dependency and Binary Discovery | Proposed |
| L4 | Runtime Cryptographic Behaviour Discovery | Proposed |
| L5 | Evidence Correlation and Cryptographic Inventory | Proposed |
| L6 | Quantum Risk Assessment and PQC Migration Prioritization | Proposed |

**Important:** Only L1 and L2 have preliminary Python implementations. L3–L6 are proposed future development layers.

## 3. Repository Structure

```text
Cryptoscan/
├── README.md
├── LICENSE
├── requirements.txt
├── src/
│   ├── scan_1.py
│   └── scan_2.py
├── samples/
│   ├── test_certificate.pem
│   └── nginx_test.conf
└── results/
    ├── findings.json
    └── findings_l2.json
```

## 4. Requirements

- Python 3.10 or later
- Python cryptography library
- Windows, Linux or macOS

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## 5. Running the Scanners

Run commands from the repository's main directory.

### L1 – Certificate and Key Discovery

```bash
python src/scan_1.py samples -o results/findings.json
```

This scanner identifies supported X.509 certificates and public/private key formats, and reports:

- Cryptographic algorithm
- Key size
- Certificate signature algorithm
- Certificate expiration status
- Simplified classification of algorithms considered vulnerable to sufficiently capable quantum computers

### L2 – Cryptographic Configuration Discovery

```bash
python src/scan_2.py samples -o results/findings_l2.json
```

This scanner examines supported configuration files for selected cryptographic indicators, including:

- Deprecated TLS/SSL protocols
- Weak or deprecated cipher algorithms
- RSA, DH and elliptic-curve mechanisms
- Selected SSH cryptographic settings
- Selected OpenSSL and Java security settings

Both scanners operate offline and are designed for read-only inspection.

### Windows Python Launcher

If using Python 3.13 on Windows, the equivalent commands are:

```cmd
py -3.13 src/scan_1.py samples -o results/findings.json
```

```cmd
py -3.13 src/scan_2.py samples -o results/findings_l2.json
```

## 6. Preliminary Test Results

Controlled tests were conducted using a self-signed RSA-2048 certificate and a sample Nginx configuration file.

### L1 Test

| Test item | Result |
|---|---|
| Certificate detected | Yes |
| Algorithm | RSA |
| Key size | 2048 bits |
| Quantum-vulnerability flag | True |
| JSON output | Generated |

### L2 Test

| Configuration indicator | Detection | Severity |
|---|---|---|
| TLSv1 | Deprecated protocol | HIGH |
| RC4 | Weak/deprecated algorithm | HIGH |
| prime256v1 | Elliptic-curve mechanism | QUANTUM |

The QUANTUM label is a prototype classification indicating an algorithm family considered vulnerable to sufficiently capable quantum computers; it is not a standardized severity rating.

**L2 test summary:** One configuration file examined and three findings detected.

These results demonstrate preliminary detection capability on controlled test samples. They do not establish enterprise-scale accuracy or comprehensive cryptographic discovery.

## 7. Output

The scanners generate JSON reports:

- `results/findings.json`
- `results/findings_l2.json`

The L1 report includes a prototype cryptographic inventory representation. It is not claimed to be compliant with the official CycloneDX CBOM specification.

## 8. Research Limitations

- L1 and L2 are preliminary implementations.
- L2 uses pattern-based configuration analysis.
- Findings require manual contextual validation.
- Effective runtime cryptographic settings are not verified.
- A quantum-vulnerability flag does not indicate an actual quantum attack.
- The risk classification is exploratory, not a validated probability model.
- L3–L6 have not yet been implemented.
- Production readiness and enterprise-scale performance have not been established.

The prototype is intended for research and educational evaluation.

**Security note:** Scan only files and systems you are authorized to inspect. Do not upload real private keys, passwords or confidential configuration files to this public repository.

## 9. Future Development

Planned research and development activities include:

1. Library, dependency and binary discovery.
2. Runtime cryptographic behaviour observation.
3. Evidence correlation and normalized cryptographic inventory.
4. Quantum risk assessment and migration prioritization.
5. Broader reproducible testing and validation.

## 10. Citation

Angajala, S. R. (2026). *CryptoScan: A Source-Code-Independent Framework for Legacy Cryptographic Discovery*. Zenodo.

https://doi.org/10.5281/zenodo.23955931

## 11. Licence

This software is released under the MIT License. See [LICENSE](LICENSE).

## 12. Author

**Dr. Srinivasa Rao Angajala**  
Independent Researcher  
Guntur, Andhra Pradesh, India
