<h3 style="text-align: center;">
  <a href="https://fhir.saude.go.gov.br"><img src="./docs/image/safira-logo.png" alt="HubSaúde (logo)" width="300"></a>
  <br>
  Sistema de Assinatura FHIR Avançada
  <br>
</h3>

Implementação de Software da criação de assinatura digital e a correspondente verificação conforme definidas no [Guia de Segurança da Informação em Saúde da SES-GO](https://fhir.saude.go.gov.br/r4/seguranca/).

## Software Design
https://github.com/FabricaDeSoftwareINF/server-hubsaude/tree/develop/safira

## CLI para testar com certificado real

Utilitário de linha de comando para executar a pipeline completa de assinatura usando um certificado PKCS#12 (`.pfx`/`.p12`) real — útil para testar com um certificado ICP-Brasil sem expor o arquivo.

**Build:**
```bash
mvn -pl modules/safira-rest -am package -DskipTests
```

**Execução com os exemplos prontos:**
```bash
java -cp modules/safira-rest/target/safira-rest-1.0.0-SNAPSHOT.jar \
     br.gov.go.saude.fhir.safira.rest.cli.SafiraSigningCli \
     /caminho/para/sua-chave.pfx \
     "sua-senha" \
     examples/bundle.json \
     examples/provenance.json
```

**Sintaxe geral:**
```bash
java -cp modules/safira-rest/target/safira-rest-*.jar \
     br.gov.go.saude.fhir.safira.rest.cli.SafiraSigningCli \
     <pfx-path> <senha> <bundle.json> [provenance.json]
```

- `pfx-path` — caminho para o PKCS#12
- `senha` — senha do PKCS#12
- `bundle.json` — Bundle FHIR a assinar
- `provenance.json` — (opcional) Provenance FHIR. Se omitido, um Provenance mínimo é gerado referenciando todas as entries do Bundle.

O alias da chave privada e a cadeia de certificados são extraídos automaticamente do PKCS#12. A saída é o recurso FHIR `Signature` em JSON em stdout. Em caso de falha, um `OperationOutcome` é impresso em stderr.

Os arquivos de exemplo em `examples/` contêm um Bundle com `Patient` + `Observation` (com referência cruzada) e um `Provenance` que aponta para as duas entries — prontos para assinatura.

## Backlog

- Validação de cadeia (`chain-validation`) ausente no YAML de testes — não é possível testar sem expor chave privada/senha de certificado real em código. Ativar quando houver mecanismo seguro de teste com certificados.
- Validação de referências internas (`PayloadValidationStep.verifyInnerContentReferences`) — chamada comentada em `PayloadValidationStep.java:41-42`. Definir abordagem de implementação e descomentar.
- `HttpTsaClient` — integração HTTP real com TSA externa (RFC 3161)
- PKCS#11 (SMARTCARD/TOKEN) — suporte a dispositivos criptográficos
- Remote signing — suporte a assinatura remota
- Pipeline de verificação — steps de verificação da assinatura
- Curvas ECDSA além de P-256 (`CryptoSigningStep`)
- Tipo de assinatura dinâmico no `FhirSignatureStep` (hoje fixo em "Author's Signature")

## Observações sobre a especificação (Criar Assinatura — Etapas 1-14)

As seguintes observações foram identificadas durante auditoria sênior do código contra a especificação:

- **Etapa 7.4 (iat vs sigT):** A especificação afirma corretamente que `iat` e `sigPId` são definidas pelo JAdES. Confirmado pela ETSI TS 119 182-1 V1.2.1 (2024-07), seção 5.1.11: a partir de 2025-07-15, `iat` (NumericDate inteiro) substitui `sigT` (RFC 3339) em novas assinaturas.
- **Etapa 7.4 (iat em TSA):** A especificação define `iat` apenas para estratégia IAT. Porém, JAdES-B-B exige claimed signing time (`iat`) sempre, independente da estratégia. Sugestão: incluir `iat` no protected header para ambas as estratégias (IAT e TSA).
- **Etapa 14.2 (extração CPF/CNPJ):** A especificação diz "extraia do campo **subject** do certificado o atributo com OID 2.16.76.1.3.3". Na prática ICP-Brasil (DOC-ICP-04), CPF/CNPJ vivem no SubjectAlternativeName (SAN, otherName), não no subject DN. A implementação usa SAN (correto na prática), mas diverge da letra da especificação.
- **Etapa 1.2 (intervalo do timestamp):** A especificação define intervalo `[1751328000, 4102444800]` (1 jul 2025 a 31 dez 2099). O YAML de configuração usa `[1751328000, 4102444800]` (1 jul 2025 a 1 jan 2100). Divergência mínima no limite superior: a spec diz "31 dezembro 2099" mas 4102444800 é exatamente 2100-01-01T00:00:00Z, não 2099-12-31T23:59:59Z.
- **Estrutura JWS (etapas 12-13):** Componentes unsigned (`sigTst`, `rRefs`) devem ficar dentro do array `etsiU` no unprotected header conforme ETSI TS 119 182-1 seção 5.3.1 — não soltos em `signatures[0].header`. Ver `AUDITORIA-JADES-B.md` para detalhes das divergências JAdES.