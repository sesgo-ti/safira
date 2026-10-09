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
| `safira-simulador` | Aplicação do simulador (JAR `-exec`): a API do `safira-rest` com uma PKI simulada no lugar do acervo ICP-Brasil (sem valor legal, sem rede, sem a icpbrasil-truststore); o jar comum é biblioteca (auto-configuração e gerador de PKI simulada) |

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

> **Assinaturas simuladas não têm validade jurídica ICP-Brasil.** O simulador é uma aplicação própria (`safira-simulador`, `SimuladorApplication`, perfil `simulador` com `application-simulador.yml` — o jar comum no classpath de outra aplicação não liga o modo) sobre o `safira-rest`, sem a icpbrasil-truststore: o `safira-app` (produção) e o `safira-rest` não dependem dele. Só a fonte de confiança muda (`FonteDeConfiancaSimulada`, geração = SHA-256 do conteúdo), com revogação e carimbo do tempo sem rede: fontes locais ou em memória, a TSA online nunca é usada e as fontes online de revogação do DSS ficam presas a um `DestinationGuard` que recusa todo destino. O startup registra um aviso `WARN`, o sucesso de `POST /validar` ganha a issue "SIMULAÇÃO — sem validade jurídica ICP-Brasil" e uma assinatura simulada é recusada (`CERT.NOT-ICP-BRASIL`) por qualquer Safira em modo normal.

A PKI simulada vem do `safira-testkit` (PKI factory do EU DSS): raiz e AC marcadas `SIMULACAO - SEM VALOR LEGAL`, signatário A3-like (CPF no `otherName`), signatário revogado e TSA. Há dois modos:

- **PKI persistida** (padrão, sem âncoras configuradas): a PKI é gerada na primeira partida em `safira.simulador.diretorio` (`SAFIRA_SIMULADOR_DIRETORIO`, padrão `~/.safira-simulador/pki`) e **reutilizada** nas seguintes — mesmas raízes, então assinaturas feitas antes de um reinício continuam válidas. Revogação (OCSP e LCR) e carimbo do tempo vêm das fontes em memória da PKI carregada (as chaves da raiz, da AC e da TSA ficam em `autoridades.p12`) — a estratégia `tsa` (JAdES-B-T) funciona sem TSA externa, também depois do reinício. O revogado continua revogado; LCR e OCSP são emitidos a cada partida com validade curta (7 dias) e renovada.
- **PKI em arquivos** (âncoras configuradas): raízes, ACs e LCRs locais pelas propriedades abaixo, por exemplo com o `application-simulacao.yml` do gerador avulso. Só `iat`: sem TSA em memória, a estratégia `tsa` é recusada com `TSA.UNAVAILABLE`, sem acessar a `tsa-url`.

Conteúdo do diretório da PKI persistida:

| Arquivo | Conteúdo | Permissão (POSIX) |
|---|---|---|
| `raiz.pem`, `ac.pem` | certificados da raiz (âncora) e da AC | pública |
| `signatario.p12`, `revogado.p12` | PKCS#12 dos signatários (aliases `signatario` e `revogado`) | 0600 |
| `autoridades.p12` | chaves e certificados da raiz, da AC e da TSA | 0600 |
| `senha.txt` | senha (aleatória) de todos os PKCS#12 | 0600 |
| `lcr-raiz.crl`, `lcr-ac.crl` | LCRs regravadas a cada partida | pública |
| `pki.properties` | manifesto (formato, política, data da revogação), gravado por último | pública |

Os diretórios são criados com 0700 (sem POSIX, o log avisa que o material privado fica sem restrição). O log da partida mostra só caminhos — nunca a senha. Diretório vazio ou inexistente → gera em `<dir>.tmp` e publica com um rename atômico (uma partida abortada não deixa o diretório parcial; se o rename não couber, por exemplo num ponto de montagem, os arquivos são movidos um a um com o manifesto por último). Com arquivos → carrega e confere: PKCS#12 legíveis com a `senha.txt`, cada chave privada correspondendo ao seu certificado (desafio assinado), PEM iguais aos persistidos, cadeia raiz → AC → folhas, raiz e AC vigentes e material privado sem acesso de grupo/outros — com permissão mais aberta que 0600 a partida falha e indica o `chmod 600` (não corrige sozinho, como o ssh). Incompleto, corrompido ou inseguro → a partida falha com o diretório e o motivo (restaure o diretório ou aponte para um vazio — uma PKI nova invalida as assinaturas anteriores). Duas instâncias não abrem o mesmo diretório ao mesmo tempo: a trava `<dir>.lock` faz a segunda falhar com "em uso por outra instância". O signatário vale 2 anos; vencido ou a menos de 30 dias do vencimento, só o certificado dele é renovado na partida (mesma AC e mesma chave, serial novo; o `signatario.p12` é trocado com rename atômico) e o log pede para baixar o `signatario.p12` de novo.

> **Rede:** o simulador escuta só em `127.0.0.1` por padrão (`server.address` no `application-simulador.yml`): não há autenticação e `GET /simulacao/pki` revela o diretório da PKI. Para expô-lo (ex.: num contêiner), use `--server.address=0.0.0.0` ou `SERVER_ADDRESS=0.0.0.0`, de preferência atrás de uma rede isolada.
| Propriedade | Variável | |
|---|---|---|
| `safira.simulador.diretorio` | `SAFIRA_SIMULADOR_DIRETORIO` | diretório da PKI persistida (padrão `~/.safira-simulador/pki`) |
| `safira.simulacao.trust-anchors` | `SAFIRA_SIMULACAO_TRUST_ANCHORS` | bundle PEM com as raízes autoassinadas (vazio = PKI persistida) |
| `safira.simulacao.intermediates` | `SAFIRA_SIMULACAO_INTERMEDIATES` | bundle PEM com ACs intermediárias — opcional |
| `safira.simulacao.crls` | `SAFIRA_SIMULACAO_CRLS` | LCRs (DER/PEM) separadas por vírgula; a revogação vem só delas |
| `safira.policy.accepted-certificate-policies[0].oid` | `SAFIRA_SIMULACAO_POLICY_OID` | padrão `2.16.76.1.2.3.1` (A3) |
| `safira.policy.accepted-certificate-policies[0].issuer-sha256` | `SAFIRA_SIMULACAO_ISSUER_SHA256` | SHA-256 do DER da AC simulada |

O startup falha com mensagem clara se alguma âncora não for AC raiz autoassinada com a marca `SIMULACAO - SEM VALOR LEGAL`, chave RSA ≥ 2048 (ou EC ≥ 256) e dentro da validade, se um recurso não for `file:`/`classpath:`, se uma LCR for ilegível, vencida ou não assinada por raiz/AC configurada, ou se a allowlist não fixar o `issuer-sha256` — as mesmas conferências valem para a PKI persistida.

**1. Subir o simulador.**

```bash
./mvnw -DskipTests package
java -jar modules/safira-simulador/target/safira-simulador-*-exec.jar \
    --server.port=8090 --safira.simulador.diretorio=/tmp/safira-sim
curl -s localhost:8090/actuator/health/readiness     # {"status":"UP"}
```

O log da partida mostra se a PKI foi gerada ou reutilizada e os caminhos do material (a senha fica só em `senha.txt`):

```text
PKI simulada (SEM VALOR LEGAL) gerada em /tmp/safira-sim
  signatário (PKCS#12): /tmp/safira-sim/signatario.p12 (alias signatario)
  revogado (PKCS#12)  : /tmp/safira-sim/revogado.p12 (alias revogado)
  senha dos PKCS#12   : arquivo /tmp/safira-sim/senha.txt
  política (OID)      : 2.16.76.1.2.3.1
  validade da folha   : até 2028-10-09T19:12:13Z
```

O material público (raiz, AC e cadeia do signatário em PEM, diretório e valores da allowlist) está em `GET /simulacao/pki` — nunca chave, PKCS#12 ou senha:

```bash
curl -s localhost:8090/simulacao/pki | jq -r .raiz > raiz-simulada.pem
curl -s localhost:8090/simulacao/pki | jq -c '{diretorio, issuerSha256, politicaOid}'
```

**2. Assinar** com o `signatario.p12` e a `senha.txt` do diretório (`strategy` `iat` ou `tsa`; exemplos de `Bundle` e `Provenance` em `modules/safira-rest/src/test/resources/examples/politica-0.2.0/`):

```bash
D=/tmp/safira-sim; SENHA=$(cat $D/senha.txt); EX=modules/safira-rest/src/test/resources/examples/politica-0.2.0
P12=$(base64 < $D/signatario.p12 | tr -d '\n')
CERT=$(openssl pkcs12 -in $D/signatario.p12 -passin pass:$SENHA -nokeys -clcerts | openssl x509 -outform DER | base64 | tr -d '\n')
jq -n --slurpfile b $EX/bundle.json --slurpfile p $EX/provenance.json --arg p12 "$P12" --arg senha "$SENHA" \
      --arg cert "$CERT" --argjson ts $(date +%s) \
  '{bundle:$b[0], provenance:$p[0],
    signerCryptoMaterial:{type:"PKCS12", contentBase64:$p12, password:$senha, alias:"signatario"},
    certificateChain:[$cert], referenceTimestamp:$ts, strategy:"tsa",
    policyIdentifierUri:"https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"}' > assinar.json
curl -s -H 'Content-Type: application/json' --data @assinar.json localhost:8090/assinar > assinada.json   # 200
```

Com `revogado.p12` (alias `revogado`), a resposta é 422 com `CERT.REVOKED`.

**3. Validar:**

```bash
jq -n --slurpfile r assinada.json --slurpfile b $EX/bundle.json --argjson ts $(date +%s) \
  '{signature:$r[0].signature, bundle:$b[0], provenance:$r[0].provenance, referenceTimestamp:$ts,
    policyIdentifierUri:"https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"}' > validar.json
curl -s -H 'Content-Type: application/json' --data @validar.json localhost:8090/validar \
  | jq -c '[.issue[].details.text]'
# ["Assinatura digital validada com sucesso","SIMULAÇÃO — sem validade jurídica ICP-Brasil"]
```

**4. Reiniciar.** Pare o simulador (Ctrl+C) e suba de novo com o mesmo diretório: o log diz `reutilizada` e a `assinada.json` do passo 2 continua validando (passo 3) — inclusive a B-T (`tsa`). Conferido à mão com o JAR: assinatura `tsa` → 200; parada; segunda partida → `reutilizada`; `/validar` → `["VALIDATION.SUCCESS", …, "SIMULAÇÃO — sem validade jurídica ICP-Brasil"]`; com `autoridades.p12` corrompido, a partida termina (código 1) com `PKI simulada em <dir> corrompida: autoridades.p12 ilegível com a senha de senha.txt. …`.

Com `tsa`, o `referenceTimestamp` da validação precisa ser posterior ao carimbo mais a accuracy (regra da política, não do simulador): validar no mesmo segundo da assinatura devolve `TEMPORAL.TSA-TIMESTAMP-OUT-OF-BOUNDS`; aguarde 1–2 s.

**PKI em arquivos.** O gerador avulso grava a PKI (`raiz.pem`, `ac.pem`, `signatario.p12`, `revogado.p12`, `lcr-raiz.crl`, `lcr-ac.crl`) e um `application-simulacao.yml` com caminhos e allowlist; o simulador o usa por `--spring.config.additional-location`:

```bash
J=$(ls modules/safira-simulador/target/safira-simulador-*-exec.jar)
java -cp $J -Dloader.main=br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada \
    org.springframework.boot.loader.launch.PropertiesLauncher \
    --saida /tmp/pki [--senha <senha>] [--politica 2.16.76.1.2.3.<n>] [--cpf <cpf>]
java -jar $J --spring.config.additional-location=file:/tmp/pki/application-simulacao.yml
```

Sem `--senha`, a senha é aleatória e impressa; a informada nunca é impressa. `--politica` vale só para o signatário válido (o revogado segue `2.16.76.1.2.3.1`).

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
