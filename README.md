<h3 style="text-align: center;">
  <a href="https://fhir.saude.go.gov.br"><img src="./docs/image/safira-logo.png" alt="HubSaúde (logo)" width="300"></a>
  <br>
  Sistema de Assinatura FHIR
  <br>
</h3>

[![Build](https://github.com/sesgo-ti/safira/actions/workflows/ci.yml/badge.svg)](https://github.com/sesgo-ti/safira/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Implementação da criação e da validação de assinaturas eletrônicas qualificadas e selos eletrônicos sobre recursos FHIR R4, conforme a **Política de Assinatura 0.2.0** do [Guia de Segurança da Informação em Saúde da SES-GO](https://fhir.saude.go.gov.br/r4/seguranca/):

- política `https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0` — única versão implementada;
- JWS General JSON Serialization, **JAdES-B-B** (resultado `iat`) ou **JAdES-B-T** (resultado `tsa`), gerados e validados pelo [EU DSS](https://github.com/esig/dss) 6.4;
- canonicalização `fhir-json-lossless/0.2.0` (tokens `decimal` preservados) e artefato enquadrado `UINT64_BE` → SHA-256 como payload attached;
- certificados ICP-Brasil A3, A4, SE-S e SE-H (RSA, `RS256`), com acervo, validação PKIX (RFC 5280) e revogação OCSP/CRL da biblioteca [icpbrasil-truststore](https://github.com/sesgo-ti/icpbrasil-truststore).

## Requisitos

- Java 21
- Maven Wrapper incluso (`./mvnw`); não é preciso instalar o Maven.

## Módulos

| Módulo | Papel |
|---|---|
| `safira-engine` | Abstrações de pipeline (`Step`, `StepRegistry`, `PipelineExecutor`), JSON lossless e códigos do CodeSystem de situações excepcionais (0.2.0) |
| `safira-jades` | Integração com o EU DSS: JAdES-B-B, extensão para B-T e validação |
| `safira-steps` | Steps das pipelines de assinatura e validação da política 0.2.0 |
| `safira-rest` | API REST (Spring Boot 4) — artefato de deploy |

## Pipelines

Definidas em `safira.pipelines` (`application.yml`), chaveadas pela URI da política:

| Operação | Steps |
|---|---|
| SIGNING | `context-validation` → `payload-validation` → `pkix-chain-validation` → `certificate-policy` → `framed-content-digest` → `jades-data-to-sign` → `crypto-signing` → `jades-assemble` → `jades-extension` → `tsa-token-verification` → `fhir-signature` |
| VALIDATION | `validation-context` → `signature-binding` → `jws-structure` → `content-integrity` → `signer-certificate` → `current-chain` → `dss-validation` → `timestamp-validation` → `validation-outcome` |

O EU DSS nunca acessa a rede: as âncoras vêm do acervo ICP-Brasil (e do trust store TSA da política) e as respostas OCSP/CRL são obtidas e verificadas pela icpbrasil-truststore.

## API

Os corpos são lidos crus (`application/json`) para preservar os tokens lexicais dos elementos FHIR `decimal`; membros JSON duplicados são rejeitados.

### `POST /assinar`

```json
{
  "bundle": { "resourceType": "Bundle", "...": "..." },
  "provenance": { "resourceType": "Provenance", "target": [ ... ], "agent": [ ... ] },
  "signerCryptoMaterial": { "type": "PKCS12", "contentBase64": "...", "password": "...", "alias": "..." },
  "certificateChain": ["<certificado do signatário em Base64 DER>", "..."],
  "referenceTimestamp": 1790000000,
  "strategy": "iat",
  "policyIdentifierUri": "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"
}
```

`signerCryptoMaterial.type`: `PEM` (`privateKeyBase64`, `password` opcional) ou `PKCS12`. `referenceTimestamp` deve estar a no máximo 300 s do relógio do servidor. `strategy`: `iat` (JAdES-B-B) ou `tsa` (JAdES-B-T).

Resposta `200` (`application/fhir+json`): `{"signature": <Signature>, "provenance": <cópia do Provenance com a assinatura>}`. Falhas: `422` com `OperationOutcome` e o código do CodeSystem `situacao-excepcional-assinatura`.

### `POST /validar`

```json
{
  "signature": { "...": "Signature FHIR completa" },
  "bundle": { "...": "Bundle com os recursos assinados" },
  "provenance": { "...": "Provenance final, com a assinatura" },
  "referenceTimestamp": 1790000000,
  "policyIdentifierUri": "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"
}
```

Resposta `200` com `OperationOutcome` `VALIDATION.SUCCESS` ou `422` com o código da rejeição.

### `GET /versoes`

Políticas suportadas.

## Configuração

```yaml
icpbrasil-truststore:            # lib icpbrasil-truststore (acervo ICP-Brasil)
  storage:
    type: filesystem
  filesystem:
    base-dir: ${SAFIRA_TRUSTSTORE_DIR:/var/safira/icpbrasil-truststore}

safira:
  policy:
    accepted-certificate-policies:     # obrigatória — sem ela toda operação retorna CONFIG.INVALID-PARAMETER
      - oid: "2.16.76.1.2.3.<n>"       # OID completo (7 arcos) no ramo do tipo
        type: A3                       # A3 | A4 | SE-S | SE-H
        issuer-sha256: "<64 hex>"      # SHA-256 do DER da AC emissora imediata
    tsa-policies:                      # obrigatória para strategy=tsa e para validar JAdES-B-T
      version: "1.0.0"
      policies:
        - oid: "<OID da política da ACT>"
          max-accuracy-seconds: 1
          trust-store:
            reference: "file:/etc/safira/tsa-anchors.pem"
    temporal-policy:
      min-cert-issue-date: 1751328000
  operational:
    verification:
      tsa-url: "https://<ACT>"         # HTTPS, obrigatória para strategy=tsa
```

As demais propriedades da biblioteca (rede, revogação, política de download, readiness) estão no [README da icpbrasil-truststore](https://github.com/sesgo-ti/icpbrasil-truststore).

## Build e testes

```bash
./mvnw verify
```

Relatório de cobertura (JaCoCo) por módulo em `modules/<módulo>/target/site/jacoco/index.html`.

### Testes de integração com certificado ICP-Brasil real

Marcados com `@Tag("integration")`: não rodam no build padrão e exigem rede (ITI, AIA, OCSP/CRL) e um PKCS#12 real. Como a política aceita apenas A3, A4, SE-S e SE-H, um certificado A1 é recusado pela pipeline (`CERT.NOT-ICP-BRASIL`) após a validação PKIX real; o oráculo DSS valida um JAdES produzido com esse certificado fora da pipeline.

```bash
./mvnw -Pintegration-tests test -pl modules/safira-rest -am \
    -Dtest='RealIcpBrasil*' -Dsurefire.failIfNoSpecifiedTests=false \
    -Dpfx.path=/caminho/cert.pfx -Dpfx.password=senha
```

## Escopo e limitações

- Material criptográfico PKCS#11 (smartcard/token) e remoto: não suportados nesta versão.
- Registro de auditoria (`AuditEvent`, política C25–C29): não implementado.
- A canonicalização preserva o token de todo número JSON, sem validação FHIR R4 completa por esquema.

## Licença

Apache License 2.0 — consulte [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).

Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
