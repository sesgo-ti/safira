# Guia de configuração e execução

Passo a passo para quem nunca rodou o Safira, da clonagem até um ciclo completo de
assinatura e validação. Para referência de módulos, pipelines e endpoints, veja o
[README](../README.md); este guia é sequencial, aquele é consulta.

## 1. Pré-requisitos

- JDK 21.
- Nenhuma instalação de Maven necessária: o projeto inclui o wrapper (`./mvnw`).
- Um certificado ICP-Brasil **SE-S** (selo eletrônico em software) em PKCS#12: é
  o único tipo aceito pela política com caminho funcional pela API hoje (veja "Qual
  material criptográfico usar", no passo 4, antes de seguir em frente).
- Acesso de rede de saída, em dois momentos diferentes:
  - na subida da aplicação, para a biblioteca `icpbrasil-truststore` baixar o acervo
    oficial de `acraiz.icpbrasil.gov.br` (ITI);
  - durante o processamento de cada assinatura/validação, para resolver a cadeia do
    certificado (AIA) e consultar revogação (OCSP/CRL), endpoints de cada AC
    individual, não só do ITI. Em rede com proxy/firewall restritivo, isso costuma
    aparecer como falha de revogação durante uma chamada, não na subida da
    aplicação; vale testar os dois cenários separadamente.

## 2. Clonar e compilar

```bash
git clone git@github.com:sesgo-ti/safira.git
cd safira
./mvnw verify
```

Isso compila os quatro módulos (`safira-engine`, `safira-jades`, `safira-steps`,
`safira-rest`) e roda a suíte de testes padrão (os testes de integração com
certificado real, marcados com `@Tag("integration")`, não rodam aqui; veja a seção
9). Se `verify` terminar em `BUILD SUCCESS`, o ambiente está pronto para o próximo
passo.

## 3. O que falta configurar antes de subir

As propriedades do Safira são configuração Spring Boot padrão: ficam no
`application.yml` da aplicação que você está rodando (hoje, isso é o módulo
`safira-rest`, em `modules/safira-rest/src/main/resources/application.yml`). Esse
arquivo já vem com defaults razoáveis para quase tudo, **exceto um bloco que é
obrigatório e vem vazio**:

```yaml
safira:
  policy:
    accepted-certificate-policies: []   # <- vazio por padrão
```

Essa é a *allowlist* de políticas de certificado aceitas. Sem pelo menos uma entrada
aqui, **toda chamada a `/assinar` ou `/validar` falha** com
`CONFIG.INVALID-PARAMETER` antes mesmo de tentar processar o Bundle. A aplicação
sobe normalmente, mas nenhuma operação é concluída até essa entrada existir.

A property `icpbrasil-truststore.filesystem.base-dir` (de onde vem o acervo de
certificados ICP-Brasil, não confundir com a allowlist acima) tem um valor
configurado no `application.yml` (`${SAFIRA_TRUSTSTORE_DIR:/var/safira/icpbrasil-truststore}`),
mas **o default `/var/safira/...` normalmente não é gravável por um usuário comum em
desenvolvimento**: a aplicação falha ao subir com `Falha ao criar diretórios do
repositório: ...`. Para rodar localmente, exporte a variável apontando para um
diretório do seu usuário antes do passo 5:

```bash
export SAFIRA_TRUSTSTORE_DIR="$PWD/.data/icpbrasil-truststore"
```

Veja [`docs/trust-store.md`](trust-store.md) para o que essa biblioteca faz e como
ela é configurada.

## 4. Preenchendo a allowlist com um certificado real

A política 0.2.0 aceita certificados ICP-Brasil das categorias **A3, A4, SE-S ou
SE-H** (não aceita A1). Mas antes de extrair qualquer coisa do seu certificado, leia
a seção abaixo: ela pode te poupar de preparar um certificado que não serve.

### Qual material criptográfico usar na prática

- **A3 e A4** ficam em token/smartcard ou HSM: a chave privada não é exportável.
- **SE-H** (selo eletrônico em **hardware**) tem a mesma limitação: também fica em
  HSM, chave não exportável.
- **SE-S** (selo eletrônico em **software**) é o único com chave exportável.

A API do Safira hoje só aceita chave em **PEM** ou **PKCS#12**
(`signerCryptoMaterial.type`); suporte a PKCS#11 (smartcard/token/HSM) ainda não
existe ("Escopo e limitações" no [README](../README.md)). Na prática, **só SE-S**
tem hoje um caminho funcional de ponta a ponta pela API. A3, A4 e SE-H exigiriam
suporte a PKCS#11, que ainda não foi implementado.

### Preenchendo a allowlist

Antes de editar o YAML, vale entender **por que** essa configuração existe. A
validação de cadeia (feita pela lib `icpbrasil-truststore`, veja
[`docs/trust-store.md`](trust-store.md)) já confirma que o certificado é
genuíno e não revogado, mas isso é verdade para qualquer certificado
ICP-Brasil válido do país, de qualquer pessoa ou organização. A allowlist é
uma segunda camada, decidida por quem configura a instância: ela restringe
quais combinações de **política de certificado e Autoridade Certificadora
emissora** essa instância do Safira aceita, mesmo entre certificados
igualmente genuínos.

Um ponto importante: a allowlist **não identifica hospitais ou pessoas
específicas por CPF/CNPJ**. Ela decide só o tipo de certificado e a AC
emissora; qualquer certificado emitido sob essa combinação passa por essa
checagem. Confirmar que a pessoa/organização é quem diz ser é uma etapa
separada e posterior, comparando o `Provenance.agent` com a identidade real
do certificado (veja o aviso no passo 6).

Cada entrada da allowlist precisa de três valores, extraídos do certificado que você
pretende usar para assinar: o **OID** da política do certificado, o **tipo**
(`A3`, `A4`, `SE-S` ou `SE-H`, derivado do próprio OID, não extraído
separadamente) e o **SHA-256** do certificado da AC emissora imediata. As
seções abaixo mostram como chegar ao certificado do signatário e ao da AC
emissora a partir do material que você recebeu (`.pfx`, `.cer`/`.crt`, `.p7b`);
a última seção deste passo volta a esses três valores e monta a entrada
completa.

### Extraindo o certificado do signatário e o da AC emissora de um PKCS#12

Se você recebeu o material como um único arquivo `.pfx`/`.p12`:

> **Arquivo antigo?** O OpenSSL 3 não abre, por padrão, `.pfx` cifrados com
> algoritmos legados (RC2-40, 3DES), comuns em certificados ICP-Brasil mais
> antigos. Se os comandos abaixo falharem com `unsupported` ou
> `RC2-40-CBC`, adicione `-legacy` em cada um (ex:
> `openssl pkcs12 -legacy -in cert.pfx ...`).

```bash
# Certificado do signatário (folha)
openssl pkcs12 -in cert.pfx -clcerts -nokeys -out signer.pem

# Cadeia de certificados emissores (uma ou mais ACs)
openssl pkcs12 -in cert.pfx -cacerts -nokeys -out cadeia.pem
```

`cadeia.pem` pode conter mais de um certificado concatenado, **em ordem não
garantida** (não assuma que o primeiro bloco é o emissor imediato: a ordem depende
de como o `.pfx` foi montado, e muitas vezes vem a raiz primeiro). Identifique o
emissor **imediato** comparando nomes:

```bash
# Quem emitiu a folha:
openssl x509 -in signer.pem -noout -issuer

# Subject de cada certificado da cadeia (pode ter mais de um bloco):
openssl crl2pkcs7 -nocrl -certfile cadeia.pem | openssl pkcs7 -print_certs -noout
```

O bloco cujo `subject` bate com o `issuer` da folha é o emissor imediato: separe-o
num arquivo próprio (`issuer.pem`).

### Recebeu o certificado separado da chave (.cer/.crt, .p7b)?

Nem sempre o material vem tudo junto num `.pfx`. É comum a AC entregar o
certificado emitido em PKCS#7 (`.p7b`/`.p7c`, às vezes já com a cadeia
completa), e certificados avulsos em `.cer`/`.crt` (X.509) para validar a
identidade de uma AC isoladamente. Nenhum dos dois carrega a chave privada
(ela precisa vir de outro lugar, normalmente um `.pfx` separado ou um `.pem`
gerado junto com a CSR), mas servem
perfeitamente para montar o `certificateChain` da requisição: a API só exige
Base64 de DER por certificado, não importa de onde ele veio.

Se a chave vier separada, num arquivo `.pem` (comum quando certificado e
chave foram gerados a partir de uma CSR, em arquivos distintos), o Safira
aceita isso diretamente, sem precisar de um `.pfx`. No `jq` do passo 6, o
filtro está entre aspas simples, então `$(...)` não é expandido ali dentro:
siga o mesmo padrão usado para `pfx`, passando o valor por `--arg`:

```bash
--arg key "$(base64 -w0 chave.pem)" \
```

e no filtro, troque `signerCryptoMaterial` por
`{type: "PEM", privateKeyBase64: $key}` (`--arg pfx` e `--arg alias` deixam de
ser necessários nesse caso). Mantenha `--arg senha` e acrescente
`password: $senha` dentro do objeto **só se** a chave estiver cifrada no
formato tradicional do OpenSSL (veja a nota abaixo); sem senha, omita o
campo inteiro.

> **Chave cifrada?** O Safira reconhece chave sem senha em PKCS#8
> (`-----BEGIN PRIVATE KEY-----`) ou PKCS#1 (`-----BEGIN RSA PRIVATE
> KEY-----`), e chave cifrada no formato tradicional do OpenSSL
> (`-----BEGIN RSA PRIVATE KEY-----` com `Proc-Type: 4,ENCRYPTED`). Ele
> **não** reconhece `-----BEGIN ENCRYPTED PRIVATE KEY-----` (PKCS#8 cifrado),
> que é o formato padrão gerado pelo OpenSSL 3 ao cifrar uma chave. Se a sua
> começar assim, decifre antes de usar:
>
> ```bash
> openssl pkey -in chave.pem -out chave-aberta.pem
> ```
>
> A chave decifrada fica em texto puro no disco: trate `chave-aberta.pem` com
> o mesmo cuidado que a original cifrada, e apague-a assim que terminar de
> testar.

**De um `.cer`/`.crt` avulso:**

O comando abaixo converte **um** certificado para PEM e gera o arquivo
`signer.pem`/`issuer.pem` que os próximos passos esperam; ele não sabe nem se
importa se é o do signatário ou o da AC emissora, nem se o arquivo de entrada
é PEM ou DER (o OpenSSL 3 detecta sozinho). Use-o pra cada arquivo `.cer` que
você tiver, nomeando a saída conforme o papel dele:

```bash
openssl x509 -in signer.cer -out signer.pem
```

> Em versões antigas do OpenSSL (1.1 ou anteriores), a detecção automática de
> formato pode não funcionar; se o comando acima falhar, verifique se o
> arquivo é texto (`-----BEGIN CERTIFICATE-----`) ou binário com `file
> signer.cer` e adicione `-inform der` se for binário.

**De um `.p7b`/`.p7c` (certificado e cadeia, sem chave):**

```bash
# Extrai todos os certificados do pacote para um único arquivo PEM concatenado
# (troque -inform der por -inform pem se o .p7b vier como texto, com
# -----BEGIN PKCS7-----)
openssl pkcs7 -in cadeia.p7b -inform der -print_certs -out cadeia.pem
```

O `cadeia.pem` resultante tem vários certificados concatenados, em ordem não
garantida, igual ao extraído do `.pfx` acima, mas com uma diferença
importante: o `.p7b` normalmente **inclui o certificado do próprio
signatário**, não só a cadeia de emissores (o `-cacerts` do `.pfx`
deliberadamente exclui a folha; o `.p7b` em geral não). Use os mesmos
comandos de `subject`/`issuer` de cima pra separar os blocos: o bloco cujo
`subject` é o seu (o CNPJ/razão social no `CN`) é o signatário, separe-o como
`signer.pem`; entre os blocos restantes, o emissor imediato é o que tem
`subject` igual ao `issuer` da folha, separe-o como `issuer.pem`.

### Encontrando o alias do PFX

Necessário para `signerCryptoMaterial.alias` (passo 6). O `friendlyName` do OpenSSL
nem sempre aparece; o `keytool` do JDK (já um pré-requisito) mostra o alias
exatamente como o Safira vai ler:

```bash
keytool -list -keystore cert.pfx -storetype PKCS12
```

### Obtendo os três valores e preenchendo a entrada

```bash
# 1. OID da política de certificado (procure "Certificate Policies" na saída)
openssl x509 -in signer.pem -noout -text | grep -A2 "Certificate Policies"
```

O `oid` da allowlist é o valor completo impresso depois de "Policy:", exatamente
como o OpenSSL retornou, sem editar nada: precisa ter sete arcos numéricos e
começar com o ramo da categoria correspondente. O `type` não vem de nenhum
comando separado, você o identifica pelo prefixo desse mesmo OID: começando em
`2.16.76.1.2.3.` é `type: A3`; em `2.16.76.1.2.4.`, `type: A4`; em
`2.16.76.1.2.201.`, `type: SE-S`; em `2.16.76.1.2.202.`, `type: SE-H`.

```bash
# 2. SHA-256 do DER do certificado da AC emissora imediata
# (openssl dgst sozinho imprime um prefixo antes do hash, não cole isso no YAML;
# a opção -r e o cut abaixo já descartam esse prefixo)
openssl x509 -in issuer.pem -outform der | openssl dgst -sha256 -r | cut -d' ' -f1
```

Esse é o `issuer-sha256` da allowlist, em minúsculo. Mantenha entre aspas,
como no exemplo: sem elas, um hash composto só por dígitos e começando com
`0` seria lido pelo YAML como número, não como texto.

Com os três valores em mãos, monte a entrada completa. Por exemplo, se o
comando 1 retornou `2.16.76.1.2.201.5` e o comando 2 retornou `a1b2c3...` (64
caracteres hex):

```yaml
safira:
  policy:
    accepted-certificate-policies:
      - oid: "2.16.76.1.2.201.5"
        type: SE-S
        issuer-sha256: "a1b2c3...<64 hex minúsculo>"
```

Adicione essa entrada no `application.yml` da aplicação (hoje,
`modules/safira-rest/src/main/resources/application.yml`), ou sobreponha via um
profile/arquivo externo/variável de ambiente, se preferir não versionar o valor.

## 5. Subindo a aplicação

```bash
./mvnw -pl modules/safira-rest -am spring-boot:run
```

Na primeira subida, a biblioteca `icpbrasil-truststore` baixa o acervo oficial de
Autoridades Certificadoras do ITI antes de aceitar tráfego: isso exige rede e pode
levar alguns segundos. Se o download falhar, a aplicação encerra.

## 6. Testando o fluxo de assinatura

Com um certificado já configurado na allowlist (passo 4) e o respectivo material
criptográfico (PKCS#12; veja "Qual material criptográfico usar" no passo 4), monte
a requisição conforme o exemplo do [README](../README.md#post-assinar). Os Bundles
de exemplo usados nos testes da política 0.2.0 estão em
[`modules/safira-rest/src/test/resources/examples/politica-0.2.0/`](../modules/safira-rest/src/test/resources/examples/politica-0.2.0/)
([`bundle.json`](../modules/safira-rest/src/test/resources/examples/politica-0.2.0/bundle.json),
[`provenance.json`](../modules/safira-rest/src/test/resources/examples/politica-0.2.0/provenance.json))
e podem servir de ponto de partida para `bundle`/`provenance` no corpo da
requisição.

> **Atenção ao prazo:** `referenceTimestamp` precisa estar a no máximo 300 segundos
> (±5 min) do relógio do servidor, senão a resposta é `FORMAT.INVALID-TIMESTAMP`.
> Um `request-assinatura.json` estático com um timestamp fixo deixa de funcionar
> depois de 5 minutos: gere o valor na hora da chamada, não antes. **A mesma janela
> vale para `/validar`** (seção 7).

> **O [`provenance.json`](../modules/safira-rest/src/test/resources/examples/politica-0.2.0/provenance.json)
> de exemplo não serve como está para um certificado SE-S.**
> Ele traz um agente identificado por CPF (`urn:brasil:cpf`), mas SE-S é
> certificado de **pessoa jurídica** (CNPJ). O Safira exige que algum
> `Provenance.agent.who.identifier` seja **exatamente igual** à identidade do
> certificado, senão a resposta é `VALIDATION.POLICY-COMPLIANCE-FAILED`. O
> valor precisa ser o **CNPJ com 14
> dígitos, sem pontuação**: a fonte que o Safira de fato lê é a extensão SAN
> (`otherName` `2.16.76.1.3.3`), não o `serialNumber` do subject (esse é só
> conferência opcional). Na prática, o jeito mais fácil de ler é o final do
> `CN`, que por convenção ICP-Brasil vem como `RAZÃO SOCIAL:CNPJ`. Confira
> que são 14 dígitos, sem pontuação (é uma convenção de quem emite o
> certificado, não algo que o Safira verifica):
>
> ```bash
> openssl x509 -in signer.pem -noout -subject
> ```
>
> Se preferir confirmar na extensão de verdade (menos legível, mas é a fonte
> exata): `openssl x509 -in signer.pem -noout -text` e procure
> `X509v3 Subject Alternative Name`.

Monte o corpo com `jq`, gerando o `referenceTimestamp` no momento da chamada,
substituindo o agente do `Provenance` pelo seu CNPJ e codificando o PFX e a
cadeia de certificados em Base64:

```bash
jq -n \
  --slurpfile bundle modules/safira-rest/src/test/resources/examples/politica-0.2.0/bundle.json \
  --slurpfile provenance modules/safira-rest/src/test/resources/examples/politica-0.2.0/provenance.json \
  --arg pfx "$(base64 -w0 cert.pfx)" \
  --arg senha "SENHA_DO_PFX" \
  --arg alias "ALIAS_DO_PFX" \
  --arg leaf "$(openssl x509 -in signer.pem -outform der | base64 -w0)" \
  --arg cnpj "CNPJ_DO_SEU_CERTIFICADO" \
  --argjson ts "$(date +%s)" \
  '{
    bundle: $bundle[0],
    provenance: ($provenance[0] | .agent = [{who: {identifier: {system: "urn:brasil:cnpj", value: $cnpj}}}]),
    signerCryptoMaterial: {type: "PKCS12", contentBase64: $pfx, password: $senha, alias: $alias},
    certificateChain: [$leaf],
    referenceTimestamp: $ts,
    strategy: "iat",
    policyIdentifierUri: "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"
  }' > request-assinatura.json

curl -X POST http://localhost:8080/assinar \
  -H "Content-Type: application/json" \
  -d @request-assinatura.json \
  -o resposta-assinar.json -w "HTTP %{http_code}\n"

jq . resposta-assinar.json
```

`certificateChain` é a lista de certificados em Base64 **DER** (não PEM), um por
entrada, do signatário para cima; o exemplo acima usa só o certificado-folha, que é
suficiente quando a cadeia completa pode ser resolvida via AIA.

Uma resposta `200` com `{"signature": ..., "provenance": ...}` confirma o ciclo
completo: validação de contexto → validação de cadeia PKIX → política de
certificado → assinatura JAdES → (opcional) carimbo do tempo → anexação ao
`Provenance` FHIR.

## 7. Validando uma assinatura

Pegue a `Signature`/`Provenance` produzidas no passo anterior e envie para
`/validar`, conforme o exemplo do [README](../README.md#post-validar).

> **A mesma janela de ±300s do passo 6 vale aqui** (a mesma checagem de
> política se aplica na validação). Se você reaproveitar a resposta do
> `/assinar` depois de alguns minutos, gere um `referenceTimestamp` novo: não reuse
> o do momento da assinatura.

```bash
jq -n \
  --slurpfile resp resposta-assinar.json \
  --slurpfile bundle modules/safira-rest/src/test/resources/examples/politica-0.2.0/bundle.json \
  --argjson ts "$(date +%s)" \
  '{
    signature: $resp[0].signature,
    bundle: $bundle[0],
    provenance: $resp[0].provenance,
    referenceTimestamp: $ts,
    policyIdentifierUri: "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"
  }' > request-validar.json

curl -X POST http://localhost:8080/validar \
  -H "Content-Type: application/json" \
  -d @request-validar.json
```

`resposta-assinar.json` é o arquivo salvo pelo `curl` do passo 6. Uma resposta
`200` com `OperationOutcome` `VALIDATION.SUCCESS` fecha o ciclo.

## 8. Erros comuns ao configurar pela primeira vez

| Sintoma | Causa provável | Onde corrigir |
|---|---|---|
| `Falha ao criar diretórios do repositório: /var/safira/...` ao subir | `SAFIRA_TRUSTSTORE_DIR` não sobrescrito; o default `/var/safira/...` não é gravável por um usuário comum | Passo 3 deste guia (`export SAFIRA_TRUSTSTORE_DIR=...`) |
| `CONFIG.INVALID-PARAMETER` em toda chamada a `/assinar`/`/validar` | `safira.policy.accepted-certificate-policies` vazia | Passo 4 deste guia |
| `CONFIG.MISSING-PARAMETER` mencionando `tsa-policies` | `strategy: "tsa"` usada sem `safira.policy.tsa-policies` configurado | Preencher `tsa-policies` (obrigatório só para `strategy=tsa`) ou usar `strategy: "iat"` |
| `CERT.NOT-ICP-BRASIL` ("não declara política ICP-Brasil A3, A4, SE-S ou SE-H") | Certificado usado não é A3/A4/SE-S/SE-H (ex: A1) | Trocar o certificado, pois a política não aceita A1 |
| `CERT.NOT-ICP-BRASIL` ("não consta da allowlist para o emissor \<hash\>") | OID ou `issuer-sha256` configurados no passo 4 não batem com o certificado usado (**o mais comum na primeira configuração**) | Refazer o passo 4. A mensagem traz o hash que o Safira calculou para o emissor. **Confira que é a AC esperada antes de colar esse valor no YAML**: a allowlist existe para decidir em quais ACs confiar, não para aceitar de volta qualquer emissor que apareça num erro |
| `CERT.ISSUE-DATE-TOO-OLD` | Certificado emitido antes de `2025-07-01` (default de `min-cert-issue-date`) | Usar certificado emitido após essa data, ou ajustar `safira.policy.temporal-policy.min-cert-issue-date` |
| `FORMAT.INVALID-TIMESTAMP` em `/assinar` **ou** `/validar` | `referenceTimestamp` fora da janela de ±300s do relógio do servidor | Gerar o timestamp no momento da chamada (seções 6 e 7), não reusar um valor salvo |
| `VALIDATION.POLICY-COMPLIANCE-FAILED` ("Nenhum Provenance.agent.who.identifier é integralmente igual...") | O `provenance.json` usado não tem um agente com a identidade exata do certificado (comum ao usar um certificado SE-S real com o `provenance.json` de exemplo, que traz CPF) | Passo 6 deste guia: trocar o agente pelo CNPJ/CPF do certificado usado |
| Timeout/erro ao **subir**, mencionando ITI ou download | Sem rede de saída para `acraiz.icpbrasil.gov.br` | Verificar conectividade/proxy do ambiente |
| Erro de revogação (`REVOCATION.*`) durante uma chamada, app já no ar | Sem rede de saída para o AIA/OCSP/CRL da AC específica do certificado (diferente do endpoint do ITI) | Verificar conectividade/proxy também para esses endpoints |

## 9. Testes de integração com certificado ICP-Brasil real

Cobertos no [README](../README.md#testes-de-integração-com-certificado-icp-brasil-real)
e no [`CONTRIBUTING.md`](../CONTRIBUTING.md); exigem rede externa e um PKCS#12 real,
por isso não rodam no `./mvnw verify` padrão.
