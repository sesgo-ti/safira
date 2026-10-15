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
| `safira-app` | Aplicação de produção — artefato de deploy (JAR `-exec`): `safira-rest` + adaptador do acervo ICP-Brasil (icpbrasil-truststore) e filtro de destino de rede. Não contém o modo simulação; o jar comum é biblioteca (CLI) |
| `safira-simulador` | Aplicação do simulador (JAR `-exec`): a API do `safira-rest` com uma PKI simulada no lugar do acervo ICP-Brasil (sem valor legal, sem rede, sem a icpbrasil-truststore); o jar comum é biblioteca (auto-configuração e gerador de PKI simulada) |
| `safira-cli` | Linha de comando (JAR `-exec`, picocli + Spring Boot não web): `safira assinar` e `safira validar` sobre os serviços do `safira-rest`, no modo `icpbrasil` (adaptador do `safira-app`) ou `simulacao` (PKI do `safira-simulador`) |

## Pipelines

Definidas em `safira.pipelines` (`application.yml`), chaveadas pela URI da política:

| Operação | Steps |
|---|---|
| SIGNING | `context-validation` → `payload-validation` → `pkix-chain-validation` → `certificate-policy` → `framed-content-digest` → `jades-data-to-sign` → `crypto-signing` → `jades-assemble` → `jades-extension` → `tsa-token-verification` → `fhir-signature` |
| VALIDATION | `validation-context` → `signature-binding` → `jws-structure` → `content-integrity` → `signer-certificate` → `dss-validation` → `timestamp-validation` → `validation-outcome` |

Esses steps são obrigatórios e nessa ordem (`Policy020.REQUIRED_SIGNING_STEPS` e `REQUIRED_VALIDATION_STEPS`): a configuração pode acrescentar steps, mas um pipeline da política 0.2.0 que omita ou reordene algum deles impede a partida (inclusive na CLI com `--config`). Em tempo de execução, `validation-outcome` exige a aprovação do `dss-validation` e `fhir-signature` a cadeia aprovada pelo `pkix-chain-validation`.

Na assinatura (`pkix-chain-validation`, `tsa-token-verification`) e na validação, o EU DSS decide cadeia, revogação e carimbo: as raízes do acervo ICP-Brasil (e, em B-T, o trust store TSA da política, só para a cadeia do carimbo: a do signatário precisa terminar numa raiz do acervo) são as âncoras, as ACs do acervo completam a cadeia junto com o `x5c` (sem AIA) e o próprio DSS consulta OCSP/CRL — só para cadeias que terminam numa âncora, em HTTP/HTTPS (qualquer porta) e com destinos filtrados por `icpbrasil-truststore.download-policy.*`. A icpbrasil-truststore entra como carregadora do acervo.

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

As demais propriedades da biblioteca (rede, política de download, readiness) estão no [README da icpbrasil-truststore](https://github.com/sesgo-ti/icpbrasil-truststore).

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

## CLI

`safira assinar` e `safira validar` executam **o mesmo pipeline** da API (os serviços do `safira-rest`, com o mesmo parser de requisição), sem servidor HTTP. O JAR é `modules/safira-cli/target/safira-cli-<versão>-exec.jar`.

```bash
safira assinar --bundle b.json --provenance p.json --p12 a.p12 \
    (--senha-arquivo s.txt | --senha-env VAR | --senha-stdin) [--alias A] --estrategia iat|tsa \
    [--politica <uri>] [--saida out.json] [--modo icpbrasil|simulacao] [--pki-dir DIR] [--timeout-acervo S] [--config extra.yml] [--verbose]
safira validar --signature s.json --bundle b.json --provenance p.json \
    [--politica <uri>] [--saida r.json] [--modo icpbrasil|simulacao] [--pki-dir DIR] [--timeout-acervo S] [--config extra.yml] [--verbose]
```

- **Saída:** o stdout recebe só o JSON de resultado — em `assinar`, o mesmo envelope `{"signature", "provenance"}` de `POST /assinar`; em `validar`, o `OperationOutcome`; em falha, o `OperationOutcome` com o código do IG. Logs, avisos e erros vão para o stderr; stack trace só no stderr e só com `--verbose`. `--saida` grava o JSON no arquivo (stdout vazio). Se o stdout recusar a escrita (ex.: pipe fechado), a saída é 1. Sem `--verbose`, o log do Spring fica desligado (a falha de partida vira uma linha `Erro: ...`).
- **Senha:** exatamente uma de `--senha-arquivo` (uma quebra de linha final é ignorada), `--senha-env` (nome da variável) ou `--senha-stdin` (primeira linha). **Não existe `--senha <valor>`**: a senha nunca vai na linha de comando (lista de processos, histórico); um `--senha` digitado é recusado (saída 3) sem ecoar o valor nem o argumento seguinte. A senha tem no máximo 1 KiB em qualquer origem; um arquivo de senha legível por grupo ou outros (POSIX) gera um aviso no stderr (`chmod 600`).
- **Entrada:** existência e leitura dos arquivos, combinação de opções por modo e `--timeout-acervo` são conferidas antes de iniciar o Spring (no modo simulação, os arquivos dentro do diretório da PKI são conferidos depois da partida, que gera a PKI na primeira execução). Cada arquivo JSON precisa ser um único objeto UTF-8 sem membros duplicados (senão `FORMAT.JSON-MALFORMED`, saída 3). O tamanho é conferido antes da leitura e de novo na leitura (no máximo o limite + 1 byte): Bundle até `safira.operational.security.max-bundle-size` e todos os arquivos juntos até esse limite + 4 MiB, como o corpo da API (senão `SECURITY.BUNDLE-SIZE-LIMIT-EXCEEDED`, saída 3). A cadeia enviada é a do PKCS#12 (`--alias` é dispensável com uma só chave) e o instante de referência é o atual.
- **Modos (um por processo, nunca misturados):** `icpbrasil` (padrão) usa o adaptador da icpbrasil-truststore do `safira-app` — acervo sincronizado com o ITI a cada execução, num diretório **persistente** entre execuções (`SAFIRA_TRUSTSTORE_DIR`, padrão `~/.safira/icpbrasil-truststore`); sem acervo, a operação devolve `CONFIG.TRUST-STORE-EMPTY` (saída 4). **Sem rede, cada comando espera o timeout do download** antes de responder: a CLI usa 30 s e uma tentativa (a lib usa 60 s e 3 tentativas), ajustável com `--timeout-acervo <30..300>` (`icpbrasil-truststore.network.download-timeout-seconds`; fora da faixa ou fora do modo `icpbrasil` → saída 3). A allowlist institucional (`safira.policy.accepted-certificate-policies`) e a `tsa-url` vêm de `--config`. `simulacao` usa a PKI simulada persistida do simulador (mesmo diretório, `~/.safira-simulador/pki`, ou `--pki-dir`), gerada na primeira execução, sem rede e sem a icpbrasil-truststore; o stderr avisa e a saída é marcada "SIMULAÇÃO — sem validade jurídica ICP-Brasil" (membro `simulacao` no envelope de `assinar`; issue informativa no `OperationOutcome` de sucesso de `validar`). Cada modo exclui as auto-configurações do outro com precedência sobre ambiente e propriedades de sistema, e a partida exige exatamente uma `FonteDeConfianca`, do tipo do modo; `--pki-dir` fora do modo `simulacao` é erro de uso.
- **Configuração:** `safira-cli.yml` + `safira-cli-<modo>.yml` no JAR (os `application*.yml` do app e do simulador não são lidos) e `--config` (YAML adicional).

### Códigos de saída

Alinhados aos do [hubsaude CLI](https://github.com/sesgo-ti/hubsaude-cli) (0/3/4/6), mais 1 para erro interno. Na dúvida, o resultado é **inconclusivo**: uma assinatura só é dada como reprovada com evidência clara, e só sai com 0 com evidência positiva (assinatura criada; em `validar`, uma issue `VALIDATION.SUCCESS` e nenhuma `error`/`fatal`). Decide a primeira issue `error`/`fatal` do `OperationOutcome`:

| Exit | Significado | Códigos do IG |
|---|---|---|
| `0` | Sucesso: assinatura criada ou válida | `VALIDATION.SUCCESS` (sem issue de erro) |
| `3` | Erro de uso ou configuração: argumentos, arquivos, JSON, limites, política, allowlist; falha na partida (ex.: PKI simulada corrompida) | `FORMAT.*`¹, `POLICY.*`, `CONFIG.*` (exceto `TRUST-STORE-EMPTY`), `SECURITY.*` (exceto `SIGNATURE-VALIDATION-REPLAY` e `HASH-VALIDATION-FAILED`), `MIDDLEWARE.*`, `DEVICE.*`, `CRYPTO.KEY-INACCESSIBLE`, `CRYPTO.PIN-INVALID` |
| `4` | Inconclusivo: repetir mais tarde | `VALIDATION.INDETERMINATE`, `VALIDATION.TRY-LATER`, `REVOCATION.*`, `CONFIG.TRUST-STORE-EMPTY`, `TSA.UNAVAILABLE`, `TSA.INVALID-RESPONSE`, `CACHE.*`, `NETWORK.*`, `SECURITY.HASH-VALIDATION-FAILED`, `SYSTEM.TIMEOUT`; código desconhecido, issue sem código, `OperationOutcome` sem erro e sem `VALIDATION.SUCCESS` |
| `6` | Reprovação definitiva: assinatura inválida, revogado, vencido, não confiável | `CERT.*`, `CRYPTO.*` (demais), `VALIDATION.*` (demais), `TSA.*` (demais), `TEMPORAL.*`, `SECURITY.SIGNATURE-VALIDATION-REPLAY`; em `validar`, `FORMAT.JWS-MALFORMED`, `FORMAT.JADES-*`, `FORMAT.JWK-INVALID`, `FORMAT.CERT-PEM-INVALID` |
| `1` | Erro interno inesperado | `SYSTEM.*` (exceto timeout), `STORAGE.*` |

¹ Em `validar`, os `FORMAT.*` que descrevem a assinatura recebida (JWS/JAdES) são reprovação (6).

### Exemplo (modo simulação)

Conferido à mão com o JAR (a PKI é gerada na primeira execução; o `signatario.p12` e a `senha.txt` ficam no diretório):

```bash
./mvnw -DskipTests package
J=$(ls modules/safira-cli/target/safira-cli-*-exec.jar); P=/tmp/safira-sim
EX=modules/safira-rest/src/test/resources/examples/politica-0.2.0

java -jar $J assinar --modo simulacao --pki-dir $P --bundle $EX/bundle.json --provenance $EX/provenance.json \
    --p12 $P/signatario.p12 --alias signatario --senha-arquivo $P/senha.txt --estrategia iat > assinada.json
echo $?                                    # 0
jq -c 'keys' assinada.json                 # ["provenance","signature","simulacao"]
jq '.signature' assinada.json > s.json; jq '.provenance' assinada.json > p.json

java -jar $J validar --modo simulacao --pki-dir $P --signature s.json --bundle $EX/bundle.json --provenance p.json \
  | jq -c '[.issue[].details.text]'
# ["Assinatura digital validada com sucesso","SIMULAÇÃO — sem validade jurídica ICP-Brasil"]   (saída 0)

sed 's/"Souza"/"Souza-X"/' $EX/bundle.json > alterado.json
java -jar $J validar --modo simulacao --pki-dir $P --signature s.json --bundle alterado.json --provenance p.json \
  | jq -r '.issue[0].details.coding[0].code'   # CRYPTO.HASH-VERIFICATION-FAILED   (saída 6)

echo 'nao json' > lixo.json
java -jar $J validar --modo simulacao --pki-dir $P --signature lixo.json --bundle $EX/bundle.json --provenance p.json \
  | jq -r '.issue[0].details.coding[0].code'   # FORMAT.JSON-MALFORMED   (saída 3)

java -jar $J assinar --bundle $EX/bundle.json --provenance $EX/provenance.json --p12 a.p12 --estrategia iat --senha x
# stderr: Erro: argumento não reconhecido: --senha (valores omitidos).   (saída 3)
```

No modo `icpbrasil` sem acervo (ex.: `-Dicpbrasil-truststore.bootstrap.enabled=false`, sem rede) e com a allowlist por `--config`, `validar` devolve `CONFIG.TRUST-STORE-EMPTY` e sai com 4. O stderr do modo simulação traz o aviso `AVISO: SIMULAÇÃO — sem validade jurídica ICP-Brasil (PKI simulada em <dir>)` e o log da PKI (caminhos, nunca a senha).

### Servidor local

`safira servidor iniciar|parar|status` sobe a **API REST** do Safira em segundo plano, na máquina do desenvolvedor, nos dois modos: `icpbrasil` roda o `SafiraApplication` (acervo ICP-Brasil real; a 1ª partida baixa o acervo do ITI e a readiness só responde depois) e `simulacao` roda o `SimuladorApplication` (PKI simulada persistida, offline, pronto em poucos segundos). O processo filho é a mesma `java` e o mesmo JAR da CLI, com o modo imposto como em `assinar`/`validar` (exclusão das auto-configurações do outro modo e uma única `FonteDeConfianca`). **Não é implantação de produção** (o modo `icpbrasil` avisa no stderr); para produção use o `safira-app-*-exec.jar`.

```bash
safira servidor iniciar [--modo icpbrasil|simulacao] [--porta P] [--pki-dir DIR] [--config extra.yml] \
    [--timeout S] [--ociosidade 30m] [--estado-dir DIR]
safira servidor status  [--modo icpbrasil|simulacao] [--estado-dir DIR]
safira servidor parar   [--modo icpbrasil|simulacao] [--timeout S] [--estado-dir DIR]
safira simulador pki    [--pki-dir DIR]
```

- **Endereço e porta:** sempre `127.0.0.1` (sem autenticação; para expor, use o JAR do app ou do simulador). O Actuator fica no mesmo conector: um `management.server.port` de `--config` ou do ambiente é anulado, e um `management.server.address` faz o Spring Boot recusar a partida (falha fechada, saída 3). Porta: `--porta`, senão `SAFIRA_PORT`, senão `8080` (`icpbrasil`) ou `8081` (`simulacao`), para que os dois modos rodem juntos. Porta ocupada → saída 3 com a mensagem `A porta P já está em uso em 127.0.0.1`.
- **Estado:** `<estado-dir>/<modo>/` (padrão `SAFIRA_SERVIDOR_DIR` ou `~/.safira/servidor`), diretório `0700` com `servidor.properties` (PID, porta, modo, início do processo, log), `servidor.log` (stdout+stderr do servidor, recriado a cada início) e `operacao.lock`, todos `0600`. Um servidor por modo e diretório: `iniciar` com um servidor vivo sai com 3 (`já está em execução`); duas operações simultâneas no mesmo diretório também (trava). O PID só é tomado pelo servidor com identidade confirmada: mesmo instante de início **e** comando `servidor executar --modo <modo>`; início ou comando desconhecidos contam como não confirmados. Estado órfão (processo morto, ou PID vivo sem identidade confirmada — PID reaproveitado) é removido sem erro por `iniciar`, `status` e `parar`, com um aviso no stderr, e **nenhum processo alheio é encerrado**. Qualquer falha depois do fork (gravar o estado, prontidão) encerra o filho.
- **iniciar:** espera `GET /actuator/health/readiness` = 200 por até `--timeout` segundos (padrão 60 em `simulacao`, 300 em `icpbrasil`). Se o servidor morrer na partida, sai com 3 e mostra o fim do log; se não ficar pronto a tempo, o processo é encerrado, o estado removido e a saída é 4 (inconclusivo). Sucesso: saída 0 e o JSON de status (`UP`) no stdout. No Unix, o filho roda sob `nohup` e sobrevive ao fechamento do terminal.
- **status:** JSON `{"modo","estado","pid","porta","url","inicio","log"}` com `estado` `UP` (readiness 200), `DOWN` (processo vivo, readiness não responde) ou `PARADO`; sem `--modo`, `{"servidores":[...]}` com os dois modos. Saída 0 sempre que o estado é determinado.
- **parar:** SIGTERM (`ProcessHandle.destroy`, desligamento gracioso do Spring) e, após `--timeout` (padrão 30 s), encerramento forçado; remove o estado. Sem servidor, saída 0 (idempotente).
- **Ociosidade:** `--ociosidade` ou `SAFIRA_IDLE_TIMEOUT` (`90s`, `30m`, `2h` ou ISO-8601 `PT30M`; padrão: desligada) encerra o servidor depois desse tempo sem requisições; as sondas em `/actuator/**` (inclusive `status`) não contam. O estado que fica é limpo como órfão no próximo comando.
- **Modo `icpbrasil`:** acervo em `SAFIRA_TRUSTSTORE_DIR` (padrão `~/.safira/icpbrasil-truststore`, o mesmo da CLI); allowlist institucional e `tsa-url` por `--config`. Configuração: `application.yml` do `safira-app` (no modo `simulacao`, mais o `application-simulador.yml`) e `--config`.
- **`safira simulador pki`:** gera a PKI simulada na primeira vez (ou reutiliza) e imprime em JSON os caminhos (`raiz`, `ac`, `signatario`, `revogado`, `senha` — o **caminho** do arquivo, nunca a senha), os aliases, a allowlist (`politicaOid`, `issuerSha256`) e a validade do signatário.

Conferido à mão com o JAR (diretórios temporários; `pid`, instantes e caminhos variam):

```bash
J=$(ls modules/safira-cli/target/safira-cli-*-exec.jar); export SAFIRA_SERVIDOR_DIR=/tmp/safira-estado
java -jar $J servidor iniciar --modo simulacao --pki-dir /tmp/safira-sim
# stderr: AVISO: SIMULAÇÃO — sem validade jurídica ICP-Brasil; servidor local, não é implantação de produção.
# {"modo":"simulacao","estado":"UP","pid":94293,"porta":8081,"url":"http://127.0.0.1:8081","inicio":"...","log":"/tmp/safira-estado/simulacao/servidor.log"}   (saída 0, ~3 s)

java -jar $J servidor status
# {"servidores":[{"modo":"icpbrasil","estado":"PARADO"},{"modo":"simulacao","estado":"UP","pid":94293,"porta":8081,...}]}   (saída 0)

java -jar $J servidor iniciar --modo simulacao --pki-dir /tmp/safira-sim --porta 18182
# stderr: Erro: O servidor simulacao já está em execução (PID 94293, porta 8081). Use 'safira servidor parar --modo simulacao'.   (saída 3)

# corpo de /assinar com o signatario.p12, a senha.txt e a cadeia de GET /simulacao/pki (cadeiaSignatario)
curl -s -o resp.json -w '%{http_code}\n' -H 'Content-Type: application/json' --data-binary @assinar.json http://127.0.0.1:8081/assinar
# 200; jq -c keys resp.json → ["provenance","signature"]

java -jar $J servidor parar --modo simulacao
# {"modo":"simulacao","estado":"PARADO","pid":94293}   (saída 0; o log registra "Graceful shutdown complete")
java -jar $J servidor status --modo simulacao
# {"modo":"simulacao","estado":"PARADO"}   (saída 0)
```

## Integração com o hubsaude CLI

Contrato estável para o [hubsaude CLI](https://github.com/sesgo-ti/hubsaude-cli) provisionar e comandar o Safira como componente local (como faz com o validador e o simulador). O hubsaude usa a mesma `java` do seu JRE provisionado; o Safira não exige nada além do JAR.

**Artefato por release:** `safira-cli-X.Y.Z-exec.jar` (um único JAR, os dois modos) e o SHA-256 em `safira-cli-X.Y.Z-exec.jar.sha256` (só o hash em hexadecimal; gerado e conferido no `package` do `safira-cli`). Conferência manual: `shasum -a 256 safira-cli-X.Y.Z-exec.jar`. Entrada sugerida para o `release.json` do hubsaude (mesmo formato dos demais componentes):

```json
"safira": {
  "url": "https://github.com/sesgo-ti/safira/releases/download/safira-vX.Y.Z/safira-cli-X.Y.Z-exec.jar",
  "version": "X.Y.Z",
  "tag": "safira-vX.Y.Z",
  "sha256": "<conteúdo de safira-cli-X.Y.Z-exec.jar.sha256>"
}
```

**Comandos** (`--modo icpbrasil|simulacao`; `simulacao` não exige certificado ICP-Brasil nem rede):

| hubsaude | Safira |
|---|---|
| `hubsaude safira assinar ...` | `java -jar safira-cli.jar assinar ... --modo M` |
| `hubsaude safira validar ...` | `java -jar safira-cli.jar validar ... --modo M` |
| `hubsaude safira start` | `java -jar safira-cli.jar servidor iniciar --modo M [--porta P] [--ociosidade D]` |
| `hubsaude safira status` | `java -jar safira-cli.jar servidor status --modo M` |
| `hubsaude safira stop` | `java -jar safira-cli.jar servidor parar --modo M` |
| `hubsaude safira pki` | `java -jar safira-cli.jar simulador pki` |

**Variáveis:** `HUBSAUDE_SAFIRA_PORT` → `--porta P` (equivale a `SAFIRA_PORT`; padrão 8080 `icpbrasil` e 8081 `simulacao`); `HUBSAUDE_IDLE_TIMEOUT` → `--ociosidade` (equivale a `SAFIRA_IDLE_TIMEOUT`; formatos `90s`, `30m`, `2h` ou ISO-8601). O hubsaude deve passar como argumento (a CLI não lê as variáveis `HUBSAUDE_*`). Diretórios de estado e acervo: `SAFIRA_SERVIDOR_DIR`, `SAFIRA_TRUSTSTORE_DIR`, `SAFIRA_SIMULADOR_DIRETORIO` (ou `--estado-dir`, `--pki-dir`).

**Códigos de saída** (os mesmos do hubsaude CLI; detalhes em [Códigos de saída](#códigos-de-saída)): `0` sucesso; `3` erro de uso ou configuração (inclui porta ocupada e servidor já em execução); `4` inconclusivo, repetir mais tarde (inclui servidor que não ficou pronto a tempo); `6` reprovação definitiva da assinatura; `1` erro interno. O `servidor status` sai com `0` sempre que o estado é determinado: o estado vai no JSON do stdout (`UP`, `DOWN` ou `PARADO`), não no código. `servidor parar` é idempotente (`0` sem servidor). `servidor iniciar` só retorna com a readiness `UP` (saída `0` e o JSON de status) ou falha; o `url` do JSON é a base da API (`/assinar`, `/validar`).

**Garantias:**
- O servidor escuta só em `127.0.0.1`, sem autenticação, e o Actuator fica no mesmo conector. Não é implantação de produção.
- Simulação sempre marcada: aviso no stderr, membro `simulacao` no envelope de `assinar` e issue "SIMULAÇÃO — sem validade jurídica ICP-Brasil" em `validar`. Um processo nunca mistura os modos.
- A senha nunca vai por argumento: use `--senha-arquivo`, `--senha-env` ou `--senha-stdin` (`--senha` é recusado com saída 3).
- O stdout traz só o JSON de resultado; logs e erros vão para o stderr.
- Um servidor por modo e diretório de estado; PID reaproveitado nunca encerra processo alheio.

## Build e testes

```bash
./mvnw verify
```

O `package` gera o JAR executável do serviço em `modules/safira-app/target/safira-app-<versão>-exec.jar` (o jar comum do `safira-app` e o `safira-rest` são bibliotecas):

```bash
./mvnw -DskipTests package
java -jar modules/safira-app/target/safira-app-*-exec.jar
```

Relatório de cobertura (JaCoCo) por módulo em `modules/<módulo>/target/site/jacoco/index.html`.

## Release

Uma tag `vX.Y.Z` em commit da `main` dispara o workflow `release.yml`, que fixa a versão do pom a partir da tag, roda `./mvnw verify` e publica `hubsaude-safira-X.Y.Z.jar` com `checksums.txt` na release `hubsaude-safira-vX.Y.Z` de `sesgo-ti/hubsaude`. É de lá que o [hubsaude-cli](https://github.com/sesgo-ti/hubsaude-cli) provisiona o Safira, depois que a versão entra no manifesto dele.

```bash
git tag -a v0.2.0 -m "safira 0.2.0"
git push origin v0.2.0
```

A publicação exige o secret `HUBSAUDE_DIST_TOKEN` no environment `hubsaude-distribution`, com deployment policy restrita a tags `v*.*.*`.

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
