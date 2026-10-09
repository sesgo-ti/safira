/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.app.icpbrasil.SafiraIcpBrasilAutoConfiguration;
import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import br.gov.go.saude.fhir.safira.simulador.SafiraSimulacaoAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/** Opções de {@code safira servidor} conferidas sem subir processo (porta, ociosidade, isolamento dos modos). */
class ServidorOpcoesTest {

    @TempDir
    Path diretorio;

    @Test
    void shouldRefuseOccupiedPortWithClearMessage() throws Exception {
        try (ServerSocket ocupada = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            Resultado resultado = Cli.executar("servidor", "iniciar", "--modo", "icpbrasil",
                    "--estado-dir", diretorio.toString(), "--porta", String.valueOf(ocupada.getLocalPort()));

            assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
            assertThat(resultado.err()).contains("servidor local, não é implantação de produção")
                    .contains("A porta " + ocupada.getLocalPort() + " já está em uso");
            assertThat(diretorio.resolve("icpbrasil").resolve("servidor.properties")).doesNotExist();
        }
    }

    @Test
    void shouldUsePortFromEnvironmentVariable() {
        assertThat(GerenciadorDoServidor.porta(null, Map.of("SAFIRA_PORT", "9123")::get, Modo.SIMULACAO)).isEqualTo(9123);
        assertThat(GerenciadorDoServidor.porta(9000, Map.of("SAFIRA_PORT", "9123")::get, Modo.SIMULACAO)).isEqualTo(9000);
        assertThat(GerenciadorDoServidor.porta(null, Map.<String, String>of()::get, Modo.ICPBRASIL)).isEqualTo(8080);
        assertThat(GerenciadorDoServidor.porta(null, Map.<String, String>of()::get, Modo.SIMULACAO)).isEqualTo(8081);
    }

    @Test
    void shouldRefuseInvalidPort() {
        assertThatThrownBy(() -> GerenciadorDoServidor.porta(null, Map.of("SAFIRA_PORT", "abc")::get, Modo.SIMULACAO))
                .isInstanceOf(FalhaDeUso.class).hasMessageContaining("SAFIRA_PORT");
        assertThatThrownBy(() -> GerenciadorDoServidor.porta(70000, Map.<String, String>of()::get, Modo.SIMULACAO))
                .isInstanceOf(FalhaDeUso.class).hasMessageContaining("--porta");
    }

    @Test
    void shouldIsolateModesInChildArguments() {
        List<String> simulacao = ExecucaoDoServidor.argumentos(Modo.SIMULACAO, 8081, diretorio, null);
        List<String> icpbrasil = ExecucaoDoServidor.argumentos(Modo.ICPBRASIL, 8080, null, null);

        assertThat(simulacao).contains("--server.address=127.0.0.1", "--server.port=8081",
                "--safira.simulacao.enabled=true", "--safira.simulador.diretorio=" + diretorio.toAbsolutePath());
        assertThat(simulacao).anyMatch(argumento -> argumento.startsWith("--spring.autoconfigure.exclude=")
                && argumento.contains(TrustStoreAutoConfiguration.class.getName())
                && argumento.contains(SafiraIcpBrasilAutoConfiguration.class.getName()));
        assertThat(icpbrasil).contains("--server.address=127.0.0.1", "--server.port=8080",
                "--safira.simulacao.enabled=false",
                "--spring.autoconfigure.exclude=" + SafiraSimulacaoAutoConfiguration.class.getName());
        assertThat(icpbrasil).anyMatch(argumento -> argumento.startsWith("--icpbrasil-truststore.filesystem.base-dir="));
    }

    @Test
    void shouldRefuseModeSpecificOptionsInOtherMode() {
        Resultado resultado = Cli.executar("servidor", "iniciar", "--modo", "icpbrasil",
                "--estado-dir", diretorio.toString(), "--pki-dir", diretorio.toString());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.err()).contains("--pki-dir só vale com --modo simulacao");
    }
}
