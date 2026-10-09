# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado

- Política de assinatura `https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0` como única versão implementada (IG seguranca SES-GO 0.2.0), com pipelines de assinatura e de validação.
- JAdES-B-B e JAdES-B-T (ETSI TS 119 182-1) via EU DSS 6.5: protected header `{alg, x5t#S256, x5c, iat, sigPId, srCms}`, `etsiU` em claro com um único `sigTst`, carimbo com nonce, `reqPolicy` e imprint SHA-256.
- Canonicalização `fhir-json-lossless/0.2.0` e artefato enquadrado `UINT64_BE(N) || len(Ti) || Ti || len(Ri) || Ri`, sobre parser JSON sem perda (tokens `decimal` preservados, membros duplicados rejeitados).
- Elegibilidade do certificado folha por allowlist (`safira.policy.accepted-certificate-policies`: OID completo, tipo A3/A4/SE-S/SE-H e SHA-256 do emissor), RSA 2048/4096 por tipo, `digitalSignature`, identidade CPF/CNPJ com dígitos verificadores.
- Validação: parsing estrito do JWS, vínculo `Signature` × `Provenance.signature` × `Provenance.agent`, recomputação do payload, EU DSS decidindo cadeia, revogação (B-B no instante atual; B-T com o carimbo como prova de existência) e carimbo, com as regras da política 0.2.0 sobre o `TimeStampToken` e trust store TSA separado (B-T).
- Códigos do CodeSystem `situacao-excepcional-assinatura` 0.2.0.
- Maven Wrapper, workflow de CI (GitHub Actions), Dependabot, JaCoCo e separação de testes de integração por `@Tag("integration")` (perfil `integration-tests`).
- Health e probes via Spring Boot Actuator (`/actuator/health/readiness` e `/liveness`; só o endpoint `health` é exposto). A readiness só fica `UP` depois que o acervo ICP-Brasil carrega.
- Verificador central do EU DSS (`CertificateVerifierFactory` + `VerificadoresDss` sobre a porta `FonteDeConfianca`, adaptada à icpbrasil-truststore por `FonteDeConfiancaIcpBrasil`): raízes do acervo ICP-Brasil como confiáveis, compartilhadas e remontadas só na troca de geração do acervo; ACs do acervo como adjuntas, em fonte e tokens do DSS novos por operação (a adjunta é própria de cada operação), cada operação presa a uma única geração; e fontes OCSP/CRL do DSS com os timeouts de `safira.operational.verification` (`ocsp-timeout`, `crl-timeout`). Sem AIA: a cadeia é montada pelo `x5c` e pelas ACs do acervo; revogação só é buscada para cadeias que terminam numa âncora. Downloads restritos a HTTP/HTTPS (qualquer porta), sem redirecionamento nem proxy, com teto de 64 MiB por resposta e destinos filtrados na conexão (cada endereço resolvido, inclusive IPv6 de transição) pela política `icpbrasil-truststore.download-policy.*` — loopback, RFC 1918, link-local, CGNAT e ULA são recusados.
- Módulo `safira-app`, aplicação de produção e único JAR executável (`java -jar modules/safira-app/target/safira-app-*.jar`, goal `repackage` do `spring-boot-maven-plugin`): reúne o `safira-rest`, o `application.yml` de produção e o adaptador da icpbrasil-truststore (`FonteDeConfiancaIcpBrasil` e `DownloadPolicyGuard`, pacote `app.icpbrasil`). Só ele depende da lib. Sem bean `FonteDeConfianca` ou `DestinationGuard` a aplicação não sobe (falha fechada).
- Modo simulação (módulo `safira-simulador`, perfil `simulacao`, fora do produto): assina e valida pelo mesmo pipeline com raízes de confiança próprias (`safira.simulacao.trust-anchors`, `intermediates`, `crls`) entregues pela porta `FonteDeConfianca` (`FonteDeConfiancaSimulada`, geração = SHA-256 do conteúdo), sem a icpbrasil-truststore e sem rede (`DestinationGuard` que recusa todo destino); LCRs locais como única fonte de revogação do DSS — sem `safira.simulacao.crls`, nada é buscado online e a revogação fica indisponível; falha na partida para âncoras ausentes, ilegíveis ou não autoassinadas; aviso `WARN` de ausência de valor legal e issue "SIMULAÇÃO — sem validade jurídica ICP-Brasil" no sucesso de `/validar` (`AvisoSimulacaoAdvice`, um `ResponseBodyAdvice` restrito à API e casado pelo padrão do mapeamento, imune a prefixo de servlet). Desligado por padrão. `safira-rest` e `safira-app` não dependem do simulador; a aplicação de simulação própria virá numa próxima etapa.
- `GeradorPkiSimulada`: gera raiz, AC, signatário A3-like (PKCS#12, CPF no `otherName`), signatário revogado, LCRs e o `application-simulacao.yml` com a allowlist — nomes marcados `SIMULACAO - SEM VALOR LEGAL`. Executável por `java -jar modules/safira-simulador/target/safira-simulador-*-exec.jar --saida <dir>`.
- Política de validação do EU DSS versionada (`safira-jades/src/main/resources/politica/safira-politica-validacao-0.2.0.xml`, derivada do `constraint.xml` do DSS 6.5), usada pelo `SignedDocumentValidator` e pelo `CertificateValidator`: extensão crítica não suportada na folha como `FAIL` e `PolicyIds` (`FAIL`) com a lista explícita dos OIDs de `safira.policy.accepted-certificate-policies`, gerada na partida (sem prefixos nem curinga). Allowlist sem OID válido recusa a operação com `CONFIG.INVALID-PARAMETER`. KeyUsage, tamanho de chave e não-CA continuam no perfil ICP-Brasil, para preservar códigos e precedência do IG.

### Alterado

- **Incompatível (deploy):** o JAR executável passa a ser o do `safira-app`; o `safira-rest` vira biblioteca (sem `main` nem `repackage`), com controller e serviços registrados por `SafiraRestAutoConfiguration`. `safira-steps` e `safira-rest` deixam de depender da icpbrasil-truststore; o `CertificateVerifierFactory` online recebe o `DestinationGuard` da aplicação.
- EU DSS atualizado de 6.4 para 6.5 (corrige DSS-3876, concorrência na validação JAdES); BouncyCastle segue alinhado em 1.86 (`bcprov`, `bcpkix`, `bcutil`), override deliberado sobre a 1.85 do DSS 6.5 (DSS-3957). Com a DSS-3954, as datas de fim de validade dos algoritmos seguem a TS 119 312 v2.1.1, o que pode mudar o resultado da validação de assinaturas com algoritmos próximos do fim de validade.
- **Incompatível:** `POST /assinar` e `POST /validar` recebem o corpo JSON cru; `/assinar` devolve `{"signature", "provenance"}` e `/validar` exige `signature`, `bundle` e `provenance`.
- **Incompatível:** a URI de política passa a ser `…/assinatura/politica/0.2.0`; URIs `…/ImplementationGuide/br.go.ses.seguranca|x.y.z` retornam `POLICY.URI-INVALID`.
- Dependência de acervo, PKIX e revogação migrada para `br.gov.go.saude:icpbrasil-truststore-autoconfigure:0.0.2` (propriedades `icpbrasil-truststore.*`). Na 0.0.2 o acervo descarta raízes fora da lista fixada (v5, v6, v7, v10, v11, v12), um certificado só é considerado revogado a partir da data de revogação e o BouncyCastle não é mais registrado na JVM; o safira usa instâncias próprias do provider.
- `Signature`: `sigFormat` `application/jose+json`, `targetFormat` `application/fhir+json`, `type` *Verification Signature* (`1.2.840.10065.1.12.1.5`).
- Assinatura B-B e extensão B-T criam o `CommonCertificateVerifier` sem AIA (o construtor padrão do DSS baixaria certificados pela rede).
- Spring Boot 4.0.7 e BouncyCastle 1.86, com versões fixadas de Netty, HttpClient 5, Jackson e Log4j por correções de segurança.
- Na criação, folha com extensão crítica não suportada ou proibida (`ocsp_noCheck`) retorna `CERT.CHAIN-VALIDATION-FAILED` (IG criar 2.7) em vez de `VALIDATION.INDETERMINATE`.
- Na criação, folha sem nenhum OID da allowlist retorna `CERT.NOT-ICP-BRASIL` (IG criar 2.5) antes de revogação, validade e extensões críticas, inclusive quando também está revogada, expirada ou ainda não é válida.

### Removido

- Passo `current-chain` (PKIX e revogação da lib no instante atual), coberto pelo `dss-validation`; a validação não usa mais `RevocationService` da icpbrasil-truststore nem monta manualmente a cadeia da TSA.
- Uso do `PkixCertificateValidator` da icpbrasil-truststore na assinatura: `pkix-chain-validation` passa a usar o `CertificateValidator` do EU DSS e `tsa-token-verification` o `DetachedTimestampValidator`, ambos sobre o verificador central; a lib fica restrita a carregar o acervo (e à política de download).

- Pipelines das políticas `0.1.0`, `1.1.0` e `2.0.0` (implementação manual de JWS e perfil JAdES com níveis B-LT/B-LTA).
- Assinatura ECDSA/ES256 (a política admite somente `RS256`).
- Propriedades `safira.jades.*`, `safira.operational.trust-store.*`, `safira.operational.validation-policy.*` (permitia revogação não estrita) e `safira.operational.security.min/max-reference-timestamp`.
- Código legado sem uso nas pipelines: steps manuais de assinatura (JWS, canonicalização JCS, cadeia, carimbo via `HttpTsaClient`) e de validação (pacote `steps.validation` fora de `jades`), `OnlineRevocationSources` e a dependência `java-json-canonicalization`. Acervo, PKIX e revogação ficam só com a icpbrasil-truststore e o EU DSS.
