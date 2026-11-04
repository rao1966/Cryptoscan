# CryptoScan
### A Source-Code-Independent Framework for Legacy Cryptographic Discovery

**Author:** Dr. Srinivasa Rao Angajala  
**Affiliation:** Independent Researcher, Guntur, Andhra Pradesh, India

**Research preprint:**  
https://doi.org/10.5281/zenodo.23955931

## Overview

CryptoScan is a research-oriented prototype designed to explore source-code-independent discovery of cryptographic artifacts in legacy and heterogeneous computing environments.

The project addresses the challenge of identifying cryptographic mechanisms when application source code or complete technical documentation is unavailable.

## Proposed Six-Layer Architecture

1. **L1 – Certificate and Key Discovery**
2. **L2 – Cryptographic Configuration Discovery**
3. **L3 – Library, Dependency and Binary Discovery**
4. **L4 – Runtime Cryptographic Behaviour Discovery**
5. **L5 – Evidence Correlation and Cryptographic Inventory**
6. **L6 – Quantum Risk Assessment and PQC Migration Prioritization**

## Current Implementation Status

The preliminary Python prototype implements:

- L1: Certificate and key-file analysis.
- L2: Rule-based cryptographic configuration scanning.

Controlled laboratory tests demonstrate detection of selected cryptographic artifacts and configuration indicators.

**Important:** L3–L6 are proposed future development layers and are not yet implemented.

## Technology

- Python
- X.509 certificate analysis
- Cryptographic configuration scanning
- Rule-based detection
- JSON-based findings

## Research Objectives

- Discover cryptographic usage in legacy systems.
- Support cryptographic inventory development.
- Explore quantum-vulnerability identification.
- Support future post-quantum cryptography migration planning.

## Project Status

Research prototype – preliminary implementation.

This project is intended for research and educational evaluation. It is not yet a production-ready enterprise cryptographic discovery solution.

## Citation

Angajala, S. R. (2026). *CryptoScan: A Source-Code-Independent Framework for Legacy Cryptographic Discovery.*

https://doi.org/10.5281/zenodo.23955931

## Licence

This software is released under the MIT License. See the LICENSE file for details.

## Author

Dr. Srinivasa Rao Angajala  
Independent Researcher  
Guntur, Andhra Pradesh, India
