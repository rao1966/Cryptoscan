# CryptoScan: Cryptographic Inventory for the Quantum Era

**A source-code-independent framework for discovering and assessing cryptographic assets in legacy IT environments.**

## 1. Overview

CryptoScan is a research prototype designed to discover, classify, and provisionally risk-rank cryptographic artifacts across legacy IT environments, including systems where source code or complete documentation may not be available.

It uses a six-layer discovery architecture and consolidates findings into a unified cryptographic inventory.

The prototype is intended for research demonstration and controlled evaluation. It has not been validated against production enterprise environments.

## 2. Architecture

| Layer | Discovery method | Scanner |
|---|---|---|
| L1 | Certificate and key discovery | `scan_1.py` |
| L2 | Configuration-file analysis | `scan_2.py` |
| L3 | Job scripts and command analysis | `scan_3.py` |
| L4 | Binary signature discovery | `scan_4.py` |
| L5 | Passive TLS/network metadata analysis | `scan_5.py` |
| L6 | Human knowledge and questionnaire ingestion | `scan_6.py` |

The reconciliation module is `reconcile_v2.py`.

## 3. Requirements

- Python 3.13.7 (tested environment).
- Python standard library.
- `cryptography` package, version 42 or later.

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

## 4. Project Structure

```text
CryptoScan/
├── scan_1.py
├── scan_2.py
├── scan_3.py
├── scan_4.py
├── scan_5.py
├── scan_6.py
├── reconcile_v2.py
├── requirements.txt
├── README.md
├── samples/
├── configs/
├── l3_test/
├── l4_test/
├── l5_test.pcap
├── l6_test.csv
├── findings.json
├── findings_l2.json
├── findings_l3.json
├── findings_l4.json
├── findings_l5_test.json
├── findings_l6_test.json
├── context_l6_test.json
├── inventory_evidence_audit.json
└── report_evidence_audit.md
```

## 5. Running the Six Scanners

Execute the following commands from the project root.

### L1 – Certificate and key discovery

```bash
python scan_1.py samples -o findings.json
```

### L2 – Configuration discovery

```bash
python scan_2.py configs -o findings_l2.json
```

### L3 – Job and script discovery

```bash
python scan_3.py l3_test -o findings_l3.json
```

### L4 – Binary signature discovery

```bash
python scan_4.py l4_test -o findings_l4.json
```

Binary signature matches indicate possible cryptographic components, not confirmed runtime use.

### L5 – Passive TLS metadata discovery

```bash
python scan_5.py l5_test.pcap -o findings_l5_test.json
```

Optional system mapping:

```bash
python scan_5.py --help
```

The scanner analyzes supplied packet captures offline. Client-offered cipher suites must not be interpreted as negotiated algorithms.

### L6 – Human knowledge ingestion

```bash
python scan_6.py l6_test.csv -o findings_l6_test.json --context-out context_l6_test.json
```

L6 findings represent human-reported information and require corroboration where possible.

## 6. Reconciliation and Risk Assessment

After generating the six findings files, run:

```bash
python reconcile_v2.py --l1 findings.json --l2 findings_l2.json --l3 findings_l3.json --l4 findings_l4.json --l5 findings_l5_test.json --l6 findings_l6_test.json --context context_l6_test.json -o inventory_evidence_audit.json --report report_evidence_audit.md
```

The reconciler produces:

- Consolidated cryptographic inventory in JSON.
- Provisional risk scores.
- Evidence provenance and evidence-strength information.
- Review flags for migration, classification, and missing context.
- Human-readable Markdown report.

## 7. Risk Model

The prototype uses:

**Risk = Vulnerability × Lifetime × Exposure**

Each factor uses an integer scale from 1 to 5.

The resulting score ranges from 1 to 125.

When lifetime or exposure information is unavailable, the prototype uses a provisional default value of 3 and flags the missing context.

These defaults are assumptions, not empirically validated measurements.

Unclassified findings are not assigned a risk score. Unknown findings must not be interpreted as low risk.

Evidence-strength labels are qualitative provenance indicators, not calibrated confidence probabilities.

## 8. Evidence and Interpretation

CryptoScan distinguishes evidence from confirmed cryptographic use.

Examples:

- Certificate discovery identifies certificate and key metadata.
- Configuration matches identify directives and configured algorithm references.
- Script matches identify cryptographic commands or API references.
- Binary signatures indicate possible embedded cryptographic components.
- PCAP observations identify network metadata and client-offered options.
- Interview records capture human-reported system knowledge.

Findings from different discovery layers may corroborate a cryptographic family without proving that they belong to the same asset.

## 9. Current Prototype Limitations

1. The prototype has been evaluated using controlled synthetic test inputs, not production enterprise estates.
2. Binary signature detection does not establish execution or runtime use.
3. Network observations do not establish successful negotiation unless the required handshake evidence is available.
4. Interview-reported information requires independent corroboration.
5. The risk model is provisional and has not been empirically calibrated.
6. Discovery coverage, false-positive rates, and false-negative rates have not yet been independently benchmarked.
7. Legacy platforms, vendor-specific formats, and additional keystore formats require further evaluation.
8. The current implementation should not be treated as a complete enterprise cryptographic inventory solution.

## 10. Research and Development Roadmap

- Expand discovery coverage for legacy enterprise formats.
- Improve binary evidence with offsets and contextual validation.
- Extend passive network analysis and handshake classification.
- Improve cross-layer asset correlation.
- Evaluate discovery accuracy against independently prepared datasets.
- Validate and calibrate the risk model.
- Evaluate migration prioritization for post-quantum cryptography.

## 11. Research Status

CryptoScan is a research prototype demonstrating a source-code-independent, six-layer approach to cryptographic discovery and provisional risk assessment.

Its current evidence consists of controlled synthetic test cases. Further implementation, benchmarking, and independent validation are required before production deployment.

## 12. Related Research

CryptoScan is associated with the research preprint:
"CryptoScan: A Source-Code-Independent Framework for Legacy Cryptographic Discovery."
The companion research manuscript will separately examine evidence provenance,
cross-layer reconciliation, and uncertainty-aware risk assessment.

## 13. License

This project is distributed under the MIT License.
See the [LICENSE](LICENSE) file for details.
