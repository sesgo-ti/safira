# Simulando o fluxo sem certificado ICP-Brasil real

Este guia resolve o problema descrito em
[`guia-configuracao-e-execucao.md`](guia-configuracao-e-execucao.md) (seção 4): sem
um certificado SE-S real (o único tipo com caminho funcional pela API hoje), não
havia como exercitar o fluxo completo de assinatura e validação. O profile
`simulado` resolve isso.

## O que o profile `simulado` faz

A política 0.2.0 depende de três coisas que só existem no mundo real: uma âncora de
confiança (acervo ICP-Brasil), verificação de revogação (OCSP/CRL) e um certificado
cuja política bata com a allowlist configurada. O profile `simulado` substitui as
três por uma **PKI fictícia gerada do zero a cada subida**: nenhuma chave fica
fixa no código.

Uma consequência direta de gerar a raiz do zero a cada subida: qualquer
`safira.policy.*` configurado no `application.yml` é **ignorado** enquanto este
profile estiver ativo. A allowlist é montada internamente para aceitar o
certificado gerado naquela execução específica, porque o SHA-256 da CA muda a
cada subida e não há como deixar isso fixo num YAML versionado.

**O que continua real:** a validação de cadeia de certificação (RFC 5280)
acontece de verdade, só ancorada numa raiz fictícia em vez do acervo oficial do
ITI. Qualquer adulteração no **conteúdo dos recursos cobertos pela assinatura**
(os `target` do `Provenance`) é rejeitada (`CRYPTO.HASH-VERIFICATION-FAILED`).
Isso **não** cobre tudo num Bundle: `id`, `meta.versionId`, `meta.lastUpdated`,
`meta.source` e `meta.tag` ficam fora do conteúdo assinado por definição da
canonicalização, e recursos que não são `target` do `Provenance` (ex: uma
`Organization` só referenciada, não assinada) também não são cobertos. Mudar
esses pontos passa validação normalmente, e isso é esperado, não uma falha do
simulador.

**O que é inteiramente simulado:** a verificação de **revogação**. A checagem
sempre responde "não revogado", sem nenhuma consulta real a OCSP/CRL. Isso é
inevitável: não existe infraestrutura real de revogação pra uma CA que só
existe na memória do processo.

> **Nota sobre o diagnóstico de `/validar`:** a mensagem de sucesso hoje sempre diz
> *"revogação conclusiva via OCSP/CRL (icpbrasil-truststore)"*, mesmo no modo
> simulado, e não reflete a origem real da verificação. É uma limitação
> conhecida, não um bug do simulador; não leve esse texto ao pé da letra enquanto
> o profile estiver ativo.

## Como usar

```bash
./mvnw install -pl modules/safira-rest -am -DskipTests
./mvnw -f modules/safira-rest/pom.xml spring-boot:run -Dspring-boot.run.profiles=simulado
```

O primeiro comando só precisa ser repetido quando você alterar código de outro
módulo, não a cada subida: veja a seção 5 do
[guia de configuração e execução](guia-configuracao-e-execucao.md) para o porquê
dos dois passos.

Nenhuma rede até ITI/AIA/OCSP/CRL é necessária nesse modo: só a rede normal de
build do Maven na primeira vez.

Ao subir, a aplicação gera uma CA e um certificado-folha novos (perfil A3) e grava
o certificado-folha e a chave privada num diretório temporário específico do seu
usuário. Os caminhos exatos aparecem no log de inicialização:

```
Simulador ativo, nunca usar em produção.
Certificado-folha e chave gerados nesta subida (válidos só enquanto esta instância estiver no ar):
  /tmp/safira-simulado-<seu-usuário>/signer.pem
  /tmp/safira-simulado-<seu-usuário>/signer-key.pem
```

A CA e o certificado são **novos a cada subida**: pare a aplicação e suba de
novo, e a allowlist passa a aceitar só o certificado gerado nessa nova
execução. Os arquivos da subida anterior **continuam fisicamente no disco**
(nada os apaga), mas deixam de ser aceitos, porque o SHA-256 da CA mudou. Monte
a requisição exatamente como no passo 6 do guia de configuração e execução,
usando o que foi gerado nesta subida:

```bash
SIM="/tmp/safira-simulado-$(whoami)"
LEAF_DER_B64=$(openssl x509 -in "$SIM/signer.pem" -outform der | base64 -w0)
KEY_B64=$(base64 -w0 "$SIM/signer-key.pem")

jq -n \
  --slurpfile bundle modules/safira-rest/src/test/resources/examples/politica-0.2.0/bundle.json \
  --slurpfile provenance modules/safira-rest/src/test/resources/examples/politica-0.2.0/provenance.json \
  --arg key "$KEY_B64" \
  --arg leaf "$LEAF_DER_B64" \
  --argjson ts "$(date +%s)" \
  '{
    bundle: $bundle[0],
    provenance: $provenance[0],
    signerCryptoMaterial: {type: "PEM", privateKeyBase64: $key},
    certificateChain: [$leaf],
    referenceTimestamp: $ts,
    strategy: "iat",
    policyIdentifierUri: "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"
  }' > request-assinatura.json

curl -X POST http://localhost:8080/assinar -H "Content-Type: application/json" -d @request-assinatura.json
```

Uma resposta `200` confirma a assinatura. Para validar, monte o corpo de `/validar`
com a `signature`/`provenance` da resposta acima, o mesmo `bundle.json` e um
`referenceTimestamp` atual, igual ao passo 7 do guia principal.

## Limitações desta primeira versão

- **Só `strategy: "iat"` (JAdES-B-B)**: o simulador não inclui uma TSA fictícia,
  então `strategy: "tsa"` (JAdES-B-T) não funciona nesse modo.
- **Só o perfil A3** é gerado hoje. Isso não contradiz a limitação de material
  criptográfico do guia principal (onde A3 real não funciona, por ser chave em
  hardware/token): aqui a chave do certificado A3 **fictício** é gerada em
  software, então nada impede o uso: é só um certificado de teste com o formato
  de um A3, não um A3 de verdade.
- **Verificação de revogação sempre "positiva"**: como explicado acima, não há
  como simular um cenário de revogação de verdade; o simulador sempre responde que
  nada está revogado.

## Nunca ativar em produção

O profile `simulado` só existe para desenvolvimento local. A cada subida, ele gera
uma CA fictícia nova e aceita qualquer certificado assinado por ela como se fosse
uma Autoridade Certificadora legítima, sem nenhuma verificação de revogação real:
qualquer "assinatura" produzida nesse modo não tem nenhum valor jurídico ou
probatório. Nenhum ambiente real deve ativar
`--spring.profiles.active=simulado`.
