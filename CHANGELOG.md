# Changelog

Todas as mudanças notáveis deste projeto serão documentadas neste arquivo.

O formato segue o [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/)
e o projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

### Adicionado

- Política de assinatura `https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0` como única versão implementada (IG seguranca SES-GO 0.2.0), com pipelines de assinatura e de validação.
- JAdES-B-B e JAdES-B-T (ETSI TS 119 182-1) via EU DSS 6.4: protected header `{alg, x5t#S256, x5c, iat, sigPId, srCms}`, `etsiU` em claro com um único `sigTst`, carimbo com nonce, `reqPolicy` e imprint SHA-256.
- Canonicalização `fhir-json-lossless/0.2.0` e artefato enquadrado `UINT64_BE(N) || len(Ti) || Ti || len(Ri) || Ri`, sobre parser JSON sem perda (tokens `decimal` preservados, membros duplicados rejeitados).
- Elegibilidade do certificado folha por allowlist (`safira.policy.accepted-certificate-policies`: OID completo, tipo A3/A4/SE-S/SE-H e SHA-256 do emissor), RSA 2048/4096 por tipo, `digitalSignature`, identidade CPF/CNPJ com dígitos verificadores.
- Validação: parsing estrito do JWS, vínculo `Signature` × `Provenance.signature` × `Provenance.agent`, recomputação do payload, cadeia PKIX atual (B-B), EU DSS com âncoras e evidências de revogação da icpbrasil-truststore, verificação do `TimeStampToken` e trust store TSA separado (B-T).
- Códigos do CodeSystem `situacao-excepcional-assinatura` 0.2.0.
- Maven Wrapper, workflow de CI (GitHub Actions), Dependabot, JaCoCo e separação de testes de integração por `@Tag("integration")` (perfil `integration-tests`).
- Health e probes via Spring Boot Actuator (`/actuator/health/readiness` e `/liveness`; só o endpoint `health` é exposto). A readiness só fica `UP` depois que o acervo ICP-Brasil carrega.
- Verificador central do EU DSS (`CertificateVerifierFactory` + `IcpBrasilCertificateVerifiers`): raízes do acervo ICP-Brasil como confiáveis, ACs do acervo como adjuntas e fontes OCSP/CRL/AIA do DSS com os timeouts de `safira.operational.verification` (`ocsp-timeout`, `crl-timeout`); downloads restritos a HTTP/HTTPS, sem redirecionamento e com teto de 64 MiB por resposta.
- `safira-rest` empacotado como JAR executável (`java -jar`), com o goal `repackage` do `spring-boot-maven-plugin`.

### Alterado

- **Incompatível:** `POST /assinar` e `POST /validar` recebem o corpo JSON cru; `/assinar` devolve `{"signature", "provenance"}` e `/validar` exige `signature`, `bundle` e `provenance`.
- **Incompatível:** a URI de política passa a ser `…/assinatura/politica/0.2.0`; URIs `…/ImplementationGuide/br.go.ses.seguranca|x.y.z` retornam `POLICY.URI-INVALID`.
- Dependência de acervo, PKIX e revogação migrada para `br.gov.go.saude:icpbrasil-truststore-autoconfigure:0.0.2` (propriedades `icpbrasil-truststore.*`). Na 0.0.2 o acervo descarta raízes fora da lista fixada (v5, v6, v7, v10, v11, v12), um certificado só é considerado revogado a partir da data de revogação e o BouncyCastle não é mais registrado na JVM; o safira usa instâncias próprias do provider.
- `Signature`: `sigFormat` `application/jose+json`, `targetFormat` `application/fhir+json`, `type` *Verification Signature* (`1.2.840.10065.1.12.1.5`).
- Assinatura B-B e extensão B-T criam o `CommonCertificateVerifier` sem AIA (o construtor padrão do DSS baixaria certificados pela rede).
- Spring Boot 4.0.7 e BouncyCastle 1.86, com versões fixadas de Netty, HttpClient 5, Jackson e Log4j por correções de segurança.

### Removido

- Pipelines das políticas `0.1.0`, `1.1.0` e `2.0.0` (implementação manual de JWS e perfil JAdES com níveis B-LT/B-LTA).
- Assinatura ECDSA/ES256 (a política admite somente `RS256`).
- Propriedades `safira.jades.*`, `safira.operational.trust-store.*`, `safira.operational.validation-policy.*` (permitia revogação não estrita) e `safira.operational.security.min/max-reference-timestamp`.
