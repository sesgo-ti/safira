# Trust Store ICP-Brasil

O Safira delega toda a gestão do acervo de certificados ICP-Brasil para uma
biblioteca externa, [`icpbrasil-truststore`](https://github.com/sesgo-ti/icpbrasil-truststore)
(`br.gov.go.saude:icpbrasil-truststore-autoconfigure`). Este documento explica o que
ela faz, o que o Safira configura dela, e onde buscar mais detalhes.

## O que o acervo contém (e o que não contém)

A ICP-Brasil é organizada em hierarquia: no topo, a AC-Raiz (mantida pelo ITI);
abaixo, várias **Autoridades Certificadoras (ACs) credenciadas**, que são quem
efetivamente emite certificados para pessoas e empresas.

A lib baixa, do repositório oficial do ITI, **apenas os certificados dessas ACs**:
a AC-Raiz e as ACs credenciadas (pouco mais de uma centena de certificados,
não milhões; o acervo de amostra dos testes da lib tem 159). Ela **não**
baixa certificados de pessoas/empresas individuais. Esse acervo serve como âncora de
confiança: ao validar a assinatura de alguém, a pipeline do Safira monta a cadeia de
certificados do signatário até uma dessas ACs e confere se ela está nesse acervo
oficial. Sem isso, não há como distinguir uma cadeia legítima de uma forjada.

## Papel dentro do Safira

A lib expõe beans Spring (`TrustStoreService`, `RevocationService`,
`CertificateChainResolver`) que os steps de `safira-steps` consomem diretamente,
notadamente nos steps de validação de cadeia PKIX e de revogação (OCSP/CRL) das
pipelines de assinatura e validação. O Safira não implementa nenhuma lógica própria
de download, cache ou verificação de cadeia: tudo isso é responsabilidade da lib.

## O que o Safira configura

Apenas uma property é de fato obrigatória: `filesystem.base-dir` (sem default na
lib, por design; veja "Por que sem default" abaixo). `storage.type` já é
`filesystem` por padrão na própria lib (`TrustStoreConfig.StorageConfig.type`); o
`application.yml` do Safira o declara explicitamente só por clareza, não porque
seja necessário:

```yaml
icpbrasil-truststore:
  storage:
    type: filesystem
  filesystem:
    base-dir: ${SAFIRA_TRUSTSTORE_DIR:/var/safira/icpbrasil-truststore}
```

`base-dir` é o diretório onde a lib guarda o acervo baixado (o `.zip` do ITI, o hash
e a confirmação da última sincronização). É um cache do pacote oficial, não
uma extração de certificados individuais. **O valor acima é o escolhido pelo Safira**
(pensando em produção), não um default da lib: veja "Para desenvolvimento local"
abaixo antes de rodar localmente.

Todas as demais properties (URLs do ITI, TTL de cache, timeouts, retries, política
de download, intervalo de sincronização) têm defaults adequados na própria lib e
normalmente não precisam ser tocadas: consulte o
[README da `icpbrasil-truststore`](https://github.com/sesgo-ti/icpbrasil-truststore#readme)
se precisar ajustar algum deles (por exemplo, para usar armazenamento S3 em vez de
filesystem, ou mudar o intervalo de atualização).

### Por que sem default

Na **lib**, `filesystem.base-dir` é, deliberadamente, a única property sem valor
padrão: é um caminho em disco, e um default "chutado" por quem a mantém poderia
escrever em lugar errado dependendo do ambiente de deploy (permissões, containers
read-only, disco sem espaço). Ela prefere falhar alto e claro na inicialização, com
uma mensagem apontando exatamente a property faltante, a silenciosamente escrever
num lugar que ninguém escolheu.

Quem escolhe um valor é cada aplicação consumidora: o **Safira** optou por
`/var/safira/icpbrasil-truststore` no `application.yml` versionado, pensando num
ambiente de produção típico, mas isso não é "o default da lib". É só o valor que o
Safira decidiu usar quando ninguém sobrescreve `SAFIRA_TRUSTSTORE_DIR`.

## Raiz de confiança personalizada

Tudo acima descreve o caminho padrão: confiar na hierarquia ICP-Brasil, via acervo
baixado do ITI. O Safira também permite **substituir inteiramente** essa fonte de
confiança por uma hierarquia própria, para integradores que assinam com
certificados fora da ICP-Brasil (por exemplo, uma AC interna da própria
organização).

A property é `safira.trust.custom-roots-dir`, apontando para um diretório com os
certificados públicos das raízes confiáveis (`.pem`, `.cer`, `.crt` ou `.der`):

```yaml
safira:
  trust:
    custom-roots-dir: /caminho/para/raizes-personalizadas
```

**É substituição, não soma**: com essa property configurada, nenhuma cadeia
ancorada no acervo ICP-Brasil é aceita, só nas raízes desse diretório. Um
certificado genuíno da ICP-Brasil passaria a ser rejeitado por falta de âncora,
da mesma forma que qualquer outro certificado fora das raízes configuradas. Não
há, hoje, suporte a somar as duas fontes de confiança.

O mecanismo é o mesmo que a própria lib usa para permitir sobrescrita: o Safira
registra um bean próprio de `TrustMaterialSource` (via
`CustomTrustAnchorConfig`), condicionado à presença dessa property
(`@ConditionalOnProperty`). Como beans de configuração do próprio app são
processados antes da auto-configuração da lib, o bean padrão dela
(`@ConditionalOnMissingBean(TrustMaterialSource.class)`) recua sozinho quando o
personalizado já existe. Sem a property, nada muda.

Como o acervo ICP-Brasil deixa de ser consultado para validação de cadeia nesse
modo, normalmente faz sentido também desligar o download/agendamento dele, para
não depender de conectividade com o ITI à toa:

```yaml
icpbrasil-truststore:
  bootstrap:
    enabled: false
  scheduling:
    enabled: false
```

Isso é uma decisão manual, não automática: configurar `custom-roots-dir` não
desliga `bootstrap`/`scheduling` sozinho, porque desligá-los tem efeito nos
clientes internos da lib (OCSP/CRL/AIA) independente da fonte de confiança
escolhida, e essa decisão cabe a cada ambiente.

Por fim, lembre que a allowlist (`safira.policy.accepted-certificate-policies`)
continua obrigatória e precisa do `issuer-sha256` da **nova** raiz (ou AC
intermediária imediata), não da ICP-Brasil: veja o
[guia de configuração e execução](guia-configuracao-e-execucao.md) para como
extrair esse valor de um certificado.

## Atualização automática

Um agendador (`TrustStoreScheduler`) verifica periodicamente (default: a cada 2h,
`icpbrasil-truststore.refresh-interval-hours`) se o ITI publicou uma nova versão do
acervo, relevante quando uma AC é descredenciada, uma nova é credenciada, ou a
própria AC-Raiz é rotacionada. Isso é sobre a **idade do acervo de ACs em si**, não
sobre o certificado individual de quem assina um documento: a validade e a
revogação do certificado do signatário são verificadas a cada assinatura/validação,
não por um monitoramento contínuo.

## Observabilidade

A auto-configuração da lib **pode** expor um health indicator (`trustStoreCache`)
em `/actuator/health`, com os estados `VALID`/`CRITICAL`/`EXPIRED`/`UNAVAILABLE`,
condicionado a `org.springframework.boot.actuate.health.HealthIndicator`
(`HealthConfiguration` da lib é `@ConditionalOnClass(HealthIndicator.class)`).

**Essa classe não existe no Actuator do Spring Boot 4**, a versão que o Safira usa
(o pacote `org.springframework.boot.actuate.health` foi removido/reestruturado;
conferido inspecionando o jar `spring-boot-actuator:4.0.7` diretamente). Isso
significa que simplesmente adicionar `spring-boot-starter-actuator` ao
`modules/safira-rest/pom.xml` **não ativa** esse indicator como numa aplicação
Spring Boot 3: a introspecção do bean tentaria carregar
`TrustStoreCacheHealthIndicator`, que implementa uma interface inexistente no
classpath, e derruba o contexto na subida. Hoje, com a versão 0.0.1 da lib, não há
como observar o estado detalhado do acervo (`VALID`/`CRITICAL`/`EXPIRED`/
`UNAVAILABLE`) via HTTP; só os endpoints genéricos do Actuator
(`health`/`readiness`/`liveness`) funcionariam, sem esse detalhe.

Se uma versão futura da lib atualizar esse indicator para o Actuator do Spring
Boot 4, o significado de cada estado e o que fazer em caso de `CRITICAL`/`EXPIRED`
está no
[manual de monitoramento da lib](https://github.com/sesgo-ti/icpbrasil-truststore/blob/main/docs/manual-monitoramento.md).

## Para desenvolvimento local

Na primeira subida, a lib baixa o acervo do ITI pela rede: isso exige
conectividade de saída. Se a rede falhar, a aplicação não sobe (comportamento
*fail-fast*, configurável via `icpbrasil-truststore.bootstrap.fail-fast`, mas manter
`true` é o recomendado mesmo em dev). Não há, hoje, um modo "offline" ou um acervo
de exemplo embutido: isso é uma dependência real de rede para qualquer ambiente,
incluindo local.

Essa dependência de rede não termina na subida: a cada assinatura/validação, a
pipeline também consulta AIA, OCSP e CRL dos endpoints específicos da AC emissora
do certificado em questão, endpoints diferentes do `acraiz.icpbrasil.gov.br` usado
só para o acervo. Em rede com proxy/firewall restritivo, é comum a subida funcionar
normalmente e só uma chamada de assinatura/validação falhar depois, por não
alcançar esses outros endpoints.

Lembre também que `SAFIRA_TRUSTSTORE_DIR` precisa apontar para um diretório
gravável pelo seu usuário: o valor versionado no `application.yml`
(`/var/safira/icpbrasil-truststore`) normalmente não é, em uma máquina de
desenvolvimento comum.
