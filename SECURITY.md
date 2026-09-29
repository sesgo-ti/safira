# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.0-SNAPSHOT (development) | :white_check_mark: |

## Reporting a Vulnerability

Safira creates and validates qualified electronic signatures and electronic seals over FHIR
resources (ICP-Brasil certificates, JAdES/JWS). Security vulnerabilities must be reported
responsibly and **never** disclosed publicly before a fix is available.

### How to report

Send an e-mail to **ti-ses.saude@goias.gov.br** with:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a minimal proof-of-concept
- The affected versions (if known)
- Any suggested remediation (optional)

### Response timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 2 business days |
| Initial assessment | 5 business days |
| Fix or workaround | Depends on severity — critical issues are prioritised |
| Public disclosure | Coordinated with the reporter after a fix is released |

### Scope

Reports are in scope for:

- Acceptance of a signature that does not satisfy signature policy 0.2.0 (content binding, protected header, certificate eligibility, chain, revocation or timestamp)
- Canonicalization ambiguities that let two different FHIR contents produce the same signed digest
- Bypass of the ICP-Brasil trust anchors or of the TSA trust store
- Private key or PIN exposure (logs, error messages, memory handling)
- Dependency vulnerabilities with a direct exploit path in this application

Out of scope: issues exclusively in test code, documentation, or dependencies that have no known exploit.

Certificate catalogue, PKIX and revocation are provided by
[icpbrasil-truststore](https://github.com/sesgo-ti/icpbrasil-truststore); report issues in that
library to its maintainers following its own `SECURITY.md`.

### Disclosure policy

We follow the principles of **responsible disclosure**. Once a fix is released we will publish a
security advisory on the GitHub repository. Credit will be given to the reporter unless they
prefer to remain anonymous.

## Operational requirements

1. **Private keys:** PEM/PKCS#12 material is sent in the signing request; deploy the REST service only behind TLS and never log request bodies.
2. **Allowlist and TSA trust stores:** `safira.policy.accepted-certificate-policies` and `tsa-policies[].trust-store.reference` define who can sign and which timestamps are accepted; protect the configuration and the PEM files against unauthorised writes.
3. **Certificate catalogue storage:** follow the residual-risk guidance of icpbrasil-truststore for `icpbrasil-truststore.filesystem.base-dir` (restrictive ACLs).
