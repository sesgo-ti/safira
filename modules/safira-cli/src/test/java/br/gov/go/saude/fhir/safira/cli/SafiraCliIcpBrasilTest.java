/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.simulador.RepositorioPkiSimulada;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Modo icpbrasil (padrão) sem acervo: o bootstrap da icpbrasil-truststore está desligado nos testes
 * (surefire), então nenhuma rede é acessada e a porta de confiança fica vazia.
 */
class SafiraCliIcpBrasilTest {

    @TempDir
    Path diretorio;

    @Test
    void shouldExitWithFourWhenTrustIsUnavailable() throws Exception {
        Path pki = diretorio.resolve("pki");
        PkiPersistida material = RepositorioPkiSimulada.abrir(pki);
        // allowlist institucional por --config: sem ela a política recusa antes de chegar à confiança
        Path config = Cli.escrever(diretorio.resolve("allowlist.yml"), """
                safira:
                  policy:
                    accepted-certificate-policies:
                      - oid: "%s"
                        type: A3
                        issuer-sha256: "%s"
                """.formatted(material.politicaOid(), material.issuerSha256()));
        Path bundle = Cli.exemplo(diretorio, "bundle.json");
        Path provenance = Cli.exemplo(diretorio, "provenance.json");

        Resultado resultado = Cli.executar("assinar", "--bundle", bundle.toString(), "--provenance", provenance.toString(),
                "--p12", pki.resolve("signatario.p12").toString(), "--alias", "signatario",
                "--senha-arquivo", pki.resolve("senha.txt").toString(), "--estrategia", "iat",
                "--config", config.toString());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
        assertThat(resultado.codigo()).isEqualTo("CONFIG.TRUST-STORE-EMPTY");
        assertThat(resultado.out() + resultado.err()).doesNotContain(AvisoSimulacaoAdvice.TEXTO);
    }
}
