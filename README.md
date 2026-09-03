<h3 style="text-align: center;">
  <a href="https://fhir.saude.go.gov.br"><img src="./docs/image/safira-logo.png" alt="HubSaúde (logo)" width="300"></a>
  <br>
  Sistema de Assinatura FHIR Avançada
  <br>
</h3>

Implementação de Software da criação de assinatura digital e a correspondente verificação conforme definidas no [Guia de Segurança da Informação em Saúde da SES-GO](https://fhir.saude.go.gov.br/r4/seguranca/).

## Software Design
https://github.com/FabricaDeSoftwareINF/server-hubsaude/tree/develop/safira

## Teste com certificado real

Teste E2E condicional que executa a pipeline completa de assinatura usando um certificado PKCS#12 (`.pfx`/`.p12`) real. Ignorado automaticamente quando as system properties não estão presentes.

**Execução:**
```bash
mvn test -pl modules/safira-rest \
    -Dtest=RealCertificateSigningIT \
    -Dpfx.path=/caminho/para/sua-chave.pfx \
    -Dpfx.password=sua-senha
```

Os arquivos de exemplo (`bundle.json` e `provenance.json`) estão em `modules/safira-rest/src/test/resources/examples/` e são carregados automaticamente pelo teste.

## Backlog

- [ ] Implementar `verifyInnerContentReferences` em `PayloadValidationStep` (hoje comentado)
- [ ] Implementar integração HTTP real com TSA externa em `HttpTsaClient` (RFC 3161)
- [ ] Suportar PKCS#11 (smartcard/token)
- [ ] Suportar assinatura remota
- [ ] Implementar pipeline de verificação de assinatura
- [ ] Suportar curvas ECDSA além de P-256 em `CryptoSigningStep`

## Licença

Apache License 2.0 — consulte [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).

Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
