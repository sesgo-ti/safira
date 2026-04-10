<h3 style="text-align: center;">
  <a href="https://fhir.saude.go.gov.br"><img src="./docs/image/safira-logo.png" alt="HubSaúde (logo)" width="300"></a>
  <br>
  Sistema de Assinatura FHIR Avançada
  <br>
</h3>

Implementação de Software da criação de assinatura digital e a correspondente verificação conforme definidas no [Guia de Segurança da Informação em Saúde da SES-GO](https://fhir.saude.go.gov.br/r4/seguranca/).

## Software Design
https://github.com/FabricaDeSoftwareINF/server-hubsaude/tree/develop/safira

## Backlog

- `HttpTsaClient` — integração HTTP real com TSA externa (RFC 3161)
- PKCS#11 (SMARTCARD/TOKEN) — suporte a dispositivos criptográficos
- Remote signing — suporte a assinatura remota
- Pipeline de verificação — steps de verificação da assinatura
- Curvas ECDSA além de P-256 (`CryptoSigningStep`)
- Tipo de assinatura dinâmico no `FhirSignatureStep` (hoje fixo em "Author's Signature")