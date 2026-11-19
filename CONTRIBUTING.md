# Contribuindo

Obrigado pelo interesse em contribuir com o **safira**!

## Pré-requisitos

- JDK 21 (Temurin recomendado)
- Não é necessário instalar Maven — use o wrapper (`./mvnw`)

## Build e testes

```bash
./mvnw verify
```

Os testes de integração (marcados com `@Tag("integration")`) dependem de rede externa
(ITI, AIA, OCSP/CRL) e de um certificado ICP-Brasil real em PKCS#12; **não** rodam no build
padrão. Para executá-los (veja o README):

```bash
./mvnw verify -Pintegration-tests -Dpfx.path=/caminho/cert.pfx -Dpfx.password=senha
```

O relatório de cobertura JaCoCo é gerado por módulo em `<módulo>/target/site/jacoco/index.html`.

## Dependências

O Dependabot abre PR semanal para atualizações do Maven e das GitHub Actions.
Para checar manualmente se algo ficou desatualizado fora desse ciclo:

```bash
./mvnw versions:display-dependency-updates
```

## Padrão de commits

Usamos [Conventional Commits](https://www.conventionalcommits.org/pt-br/) com mensagens
em **português**, em uma linha. Exemplos:

```
feat: adiciona validação do carimbo do tempo da política 0.2.0
fix: corrige mapeamento de código de revogação inconclusiva
docs: atualiza instruções de configuração da allowlist
```

## Fluxo de Pull Request

1. Crie uma branch a partir de `main`.
2. Faça as alterações com commits no padrão acima.
3. Garanta que `./mvnw verify` está verde localmente.
4. Abra o PR contra `main` e aguarde o CI (GitHub Actions) passar.

## Vulnerabilidades de segurança

Não abra issues públicas para vulnerabilidades. Siga as instruções do
[SECURITY.md](SECURITY.md) para reporte responsável.

## Política de assinatura

Toda regra implementada deriva do IG de segurança da SES-GO (política 0.2.0). Uma divergência
entre o IG e a implementação deve ser marcada no código com `// DIVERGENCIA-IG <resumo>` e
discutida com os mantenedores do IG antes de ser consolidada.

