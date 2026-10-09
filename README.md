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
- JWS General JSON Serialization, **JAdES-B-B** (resultado `iat`) ou **JAdES-B-T** (resultado `tsa`), gerados e validados pelo [EU DSS](https://github.com/esig/dss) 6.5;
- canonicalização `fhir-json-lossless/0.2.0` (tokens `decimal` preservados) e artefato enquadrado `UINT64_BE` → SHA-256 como payload attached;
- certificados ICP-Brasil A3, A4, SE-S e SE-H (RSA, `RS256`): acervo carregado pela biblioteca [icpbrasil-truststore](https://github.com/sesgo-ti/icpbrasil-truststore); cadeia, revogação OCSP/CRL e carimbos decididos pelo EU DSS.

## Requisitos

- Java 21
- Maven Wrapper incluso (`./mvnw`); não é preciso instalar o Maven.

## Módulos

| Módulo | Papel |
|---|---|
| `safira-engine` | Abstrações de pipeline (`Step`, `StepRegistry`, `PipelineExecutor`), JSON lossless e códigos do CodeSystem de situações excepcionais (0.2.0) |
| `safira-jades` | Integração com o EU DSS: JAdES-B-B, extensão para B-T e validação |
| `safira-steps` | Steps das pipelines de assinatura e validação da política 0.2.0 |
| `safira-rest` | Biblioteca da API REST (Spring Boot 4): controller e serviços registrados por auto-configuração, sem `main` |
| `safira-app` | Aplicação de produção — artefato de deploy: `safira-rest` + adaptador do acervo ICP-Brasil (icpbrasil-truststore) e filtro de destino de rede. Não contém o modo simulação |
| `safira-simulador` | Modo simulação fora do produto (porta `FonteDeConfianca` com raízes próprias, sem valor legal, sem rede) e gerador de PKI simulada (JAR executável) |

## Pipelines

Definidas em `safira.pipelines` (`application.yml`), chaveadas pela URI da política:

| Operação | Steps |
|---|---|
| SIGNING | `context-validation` → `payload-validation` → `pkix-chain-validation` → `certificate-policy` → `framed-content-digest` → `jades-data-to-sign` → `crypto-signing` → `jades-assemble` → `jades-extension` → `tsa-token-verification` → `fhir-signature` |
| VALIDATION | `validation-context` → `signature-binding` → `jws-structure` → `content-integrity` → `signer-certificate` → `dss-validation` → `timestamp-validation` → `validation-outcome` |

Na assinatura (`pkix-chain-validation`, `tsa-token-verification`) e na validação, o EU DSS decide cadeia, revogação e carimbo: as raízes do acervo ICP-Brasil (e, em B-T, o trust store TSA da política) são as âncoras, as ACs do acervo completam a cadeia junto com o `x5c` (sem AIA) e o próprio DSS consulta OCSP/CRL — só para cadeias que terminam numa âncora, em HTTP/HTTPS (qualquer porta) e com destinos filtrados por `icpbrasil-truststore.download-policy.*`. A icpbrasil-truststore entra como carregadora do acervo.

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

### Health

`GET /actuator/health/readiness` e `GET /actuator/health/liveness` (Spring Boot Actuator; só o endpoint `health` é exposto). A readiness só fica `UP` depois que o acervo ICP-Brasil carrega na partida, então orquestradores e o [hubsaude-cli](https://github.com/sesgo-ti/hubsaude-cli) aguardam por ela antes de enviar requisições. Se o acervo não carrega (rede, proxy ou ITI indisponível), o serviço encerra na partida.

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

## Modo simulação

Assina e valida pelo **mesmo pipeline** da política 0.2.0 (os steps não mudam) com uma PKI própria no lugar do acervo ICP-Brasil — para QA e para ferramentas externas (ex.: [hubsaude-cli](https://github.com/sesgo-ti/hubsaude-cli)) que não têm certificado ICP-Brasil.

> **Assinaturas simuladas não têm validade jurídica ICP-Brasil.** O modo vive só no módulo `safira-simulador`: o `safira-app` (produção) e o `safira-rest` não dependem dele. Ele é desligado por padrão e só liga com `safira.simulacao.enabled=true` (perfil `simulacao`, `application-simulacao.yml` do módulo). As raízes simuladas são a única fonte de confiança (`FonteDeConfiancaSimulada`, geração = SHA-256 do conteúdo), o startup registra um aviso `WARN`, o sucesso de `POST /validar` ganha a issue "SIMULAÇÃO — sem validade jurídica ICP-Brasil" e uma assinatura simulada é recusada (`CERT.NOT-ICP-BRASIL`) por qualquer Safira em modo normal.

| Propriedade | Variável (perfil `simulacao`) | |
|---|---|---|
| `safira.simulacao.trust-anchors` | `SAFIRA_SIMULACAO_TRUST_ANCHORS` | bundle PEM com as raízes autoassinadas — obrigatório |
| `safira.simulacao.intermediates` | `SAFIRA_SIMULACAO_INTERMEDIATES` | bundle PEM com ACs intermediárias — opcional |
| `safira.simulacao.crls` | `SAFIRA_SIMULACAO_CRLS` | LCRs (DER/PEM) separadas por vírgula; a revogação vem só delas — o modo simulação não acessa a rede |
| `safira.policy.accepted-certificate-policies[0].oid` | `SAFIRA_SIMULACAO_POLICY_OID` | padrão `2.16.76.1.2.3.999` (A3) |
| `safira.policy.accepted-certificate-policies[0].issuer-sha256` | `SAFIRA_SIMULACAO_ISSUER_SHA256` | SHA-256 do DER da AC simulada |

O startup falha com mensagem clara se as âncoras faltarem, estiverem ilegíveis ou vazias, se alguma não for AC raiz autoassinada com a marca `SIMULACAO - SEM VALOR LEGAL`, chave RSA ≥ 2048 (ou EC ≥ 256) e dentro da validade, se um recurso não for `file:`/`classpath:`, se uma LCR for ilegível, vencida ou não assinada por raiz/AC configurada, ou se a allowlist não fixar o `issuer-sha256`.

**1. Gerar a PKI simulada** (raiz, AC, `signatario.p12`, `revogado.p12` revogado na LCR, `lcr-raiz.crl`, `lcr-ac.crl` e um `application-simulacao.yml` com caminhos e allowlist) pelo JAR executável do simulador:

```bash
./mvnw -DskipTests package
java -jar modules/safira-simulador/target/safira-simulador-*-exec.jar \
    --saida /tmp/pki [--senha <senha>] [--politica 2.16.76.1.2.3.<n>] [--cpf <cpf>] [--validade-dias 365]
```

Sem `--senha`, a senha dos PKCS#12 é aleatória e impressa (aliases `signatario` e `revogado`). Os nomes trazem `SIMULACAO - SEM VALOR LEGAL`; as LCRs e os certificados folha valem `--validade-dias` (gere de novo ao expirar).

**2. Subir o serviço em modo simulação.** Ainda não há JAR de serviço em modo simulação: o `safira-app` não inclui o simulador e a aplicação de simulação própria (`safira-rest` + `safira-simulador`) é a próxima etapa. Até lá, o perfil é exercitado pelos testes de sistema do módulo, que sobem `safira-rest` + simulador com a PKI gerada:

```bash
./mvnw verify -pl modules/safira-simulador -am
```

Numa aplicação que inclua `safira-rest` e `safira-simulador`, o perfil liga com o trecho gerado (`--spring.profiles.active=simulacao --spring.config.additional-location=file:/tmp/pki/`) ou com as variáveis `SAFIRA_SIMULACAO_*` acima (o `issuer-sha256` é impresso pelo gerador).

**3. Assinar** com `POST /assinar`, `signerCryptoMaterial` `{"type":"PKCS12","contentBase64":"<signatario.p12 em Base64>","password":"<senha>","alias":"signatario"}`, `certificateChain` com o certificado do signatário (DER em Base64) e `strategy` `iat`; validar com `POST /validar`. Com `revogado.p12`, a assinatura é recusada com `CERT.REVOKED`.

## Build e testes

```bash
./mvnw verify
```

O `package` gera o JAR executável do serviço em `modules/safira-app/target/safira-app-<versão>.jar` (o `safira-rest` é biblioteca e não tem `main`):

```bash
./mvnw -DskipTests package
java -jar modules/safira-app/target/safira-app-*.jar
```

Relatório de cobertura (JaCoCo) por módulo em `modules/<módulo>/target/site/jacoco/index.html`.

### Testes de integração com certificado ICP-Brasil real

Marcados com `@Tag("integration")`: não rodam no build padrão e exigem rede (ITI, OCSP/CRL) e um PKCS#12 real. Como a política aceita apenas A3, A4, SE-S e SE-H, um certificado A1 é recusado pela pipeline (`CERT.NOT-ICP-BRASIL`) após a validação real da cadeia; o oráculo DSS valida um JAdES produzido com esse certificado fora da pipeline.

```bash
./mvnw -Pintegration-tests test -pl modules/safira-app -am \
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
