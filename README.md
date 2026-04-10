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

**Execução:**
```bash
java -cp modules/safira-rest/target/safira-rest-*.jar \
     br.gov.go.saude.fhir.safira.rest.cli.SafiraSigningCli \
     <pfx-path> <senha> <bundle.json> [provenance.json]
```

- `pfx-path` — caminho para o PKCS#12
- `senha` — senha do PKCS#12
- `bundle.json` — Bundle FHIR a assinar
- `provenance.json` — (opcional) Provenance FHIR. Se omitido, um Provenance mínimo é gerado referenciando todas as entries do Bundle.

O alias da chave privada e a cadeia de certificados são extraídos automaticamente do PKCS#12. A saída é o recurso FHIR `Signature` em JSON.

## Backlog

- `HttpTsaClient` — integração HTTP real com TSA externa (RFC 3161)
- PKCS#11 (SMARTCARD/TOKEN) — suporte a dispositivos criptográficos
- Remote signing — suporte a assinatura remota
- Pipeline de verificação — steps de verificação da assinatura
- Curvas ECDSA além de P-256 (`CryptoSigningStep`)
- Tipo de assinatura dinâmico no `FhirSignatureStep` (hoje fixo em "Author's Signature")