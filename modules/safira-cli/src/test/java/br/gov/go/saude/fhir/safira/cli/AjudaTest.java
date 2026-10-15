/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code --help}, {@code -h} e {@code help <comando>} em todos os subcomandos (saída 0 e as opções) e {@code --version}. */
class AjudaTest {

    @ParameterizedTest
    @CsvSource({
            "assinar, --estrategia",
            "validar, --signature",
            "servidor, iniciar",
            "servidor iniciar, --porta",
            "servidor parar, --timeout",
            "servidor status, --estado-dir",
            "simulador, pki",
            "simulador pki, --pki-dir"
    })
    void shouldShowHelpWithOptionsForEverySubcommand(String comando, String esperado) {
        for (String opcao : new String[] {"--help", "-h"}) {
            String[] argumentos = (comando + " " + opcao).split(" ");

            Resultado resultado = Cli.executar(argumentos);

            assertThat(resultado.saida()).isZero();
            assertThat(resultado.out()).contains(esperado).contains("--help");
        }
    }

    @Test
    void shouldShowSubcommandHelpThroughHelpCommand() {
        Resultado resultado = Cli.executar("help", "assinar");

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.out()).contains("--estrategia");
    }

    @Test
    void shouldShowArtifactVersion() {
        Resultado resultado = Cli.executar("--version");

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.out().strip()).matches("safira \\d+\\.\\d+\\.\\d+\\S*");
    }
}
