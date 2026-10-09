/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;

/**
 * {@code safira servidor iniciar|parar|status} com processo real no modo simulação (sem rede): estado em
 * diretório temporário, PKI temporária e porta livre em loopback.
 */
class ServidorTest {

    @TempDir
    Path diretorio;

    private Path estado;
    private Path pki;
    private int porta;
    private final List<Long> pids = new ArrayList<>();

    @BeforeEach
    void preparar() {
        estado = diretorio.resolve("estado");
        pki = diretorio.resolve("pki");
        porta = portaLivre();
    }

    @AfterEach
    void encerrar() {
        Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir", estado.toString());
        pids.forEach(pid -> ProcessHandle.of(pid).ifPresent(ProcessHandle::destroyForcibly));
    }

    private Resultado iniciar(String... extras) {
        List<String> argumentos = new ArrayList<>(List.of("servidor", "iniciar", "--modo", "simulacao",
                "--estado-dir", estado.toString(), "--pki-dir", pki.toString(), "--porta", String.valueOf(porta)));
        argumentos.addAll(List.of(extras));
        Resultado resultado = Cli.executar(argumentos.toArray(String[]::new));
        Matcher pid = Pattern.compile("\"pid\":(\\d+)|PID (\\d+)").matcher(resultado.out() + resultado.err());
        if (pid.find()) {
            pids.add(Long.parseLong(pid.group(1) != null ? pid.group(1) : pid.group(2)));
        }
        return resultado;
    }

    private Resultado status() {
        return Cli.executar("servidor", "status", "--modo", "simulacao", "--estado-dir", estado.toString());
    }

    private Path arquivoDeEstado() {
        return estado.resolve("simulacao").resolve("servidor.properties");
    }

    @Test
    void shouldStartSimulationServerAndReportReady() throws Exception {
        Resultado resultado = iniciar();

        assertThat(resultado.saida()).isZero();
        JsonNode json = resultado.json();
        assertThat(json.get("estado").asText()).isEqualTo("UP");
        assertThat(json.get("porta").asInt()).isEqualTo(porta);
        assertThat(json.get("url").asText()).isEqualTo("http://127.0.0.1:" + porta);
        assertThat(ProcessHandle.of(json.get("pid").asLong()).map(ProcessHandle::isAlive)).contains(true);
        assertThat(prontidao()).isEqualTo(200);
        assertThat(resultado.err()).contains("SIMULAÇÃO");
        assertThat(Files.getPosixFilePermissions(estado.resolve("simulacao")))
                .isEqualTo(PosixFilePermissions.fromString("rwx------"));
        assertThat(Files.getPosixFilePermissions(arquivoDeEstado()))
                .isEqualTo(PosixFilePermissions.fromString("rw-------"));
        assertThat(Files.getPosixFilePermissions(estado.resolve("simulacao").resolve("operacao.lock")))
                .isEqualTo(PosixFilePermissions.fromString("rw-------"));
        assertThat(Files.getPosixFilePermissions(estado.resolve("simulacao").resolve("servidor.log")))
                .isEqualTo(PosixFilePermissions.fromString("rw-------"));
    }

    @Test
    void shouldReportStatusAsJson() {
        long pid = iniciar().json().get("pid").asLong();

        Resultado resultado = status();
        Resultado agregado = Cli.executar("servidor", "status", "--estado-dir", estado.toString());

        assertThat(resultado.saida()).isZero();
        JsonNode json = resultado.json();
        assertThat(json.get("modo").asText()).isEqualTo("simulacao");
        assertThat(json.get("estado").asText()).isEqualTo("UP");
        assertThat(json.get("pid").asLong()).isEqualTo(pid);
        assertThat(json.get("porta").asInt()).isEqualTo(porta);
        assertThat(agregado.saida()).isZero();
        assertThat(agregado.json().get("servidores").findValuesAsText("modo")).containsExactly("icpbrasil", "simulacao");
        assertThat(agregado.json().get("servidores").findValuesAsText("estado")).containsExactly("PARADO", "UP");
    }

    @Test
    void shouldRefuseSecondServerInSameMode() {
        long pid = iniciar().json().get("pid").asLong();

        Resultado segundo = Cli.executar("servidor", "iniciar", "--modo", "simulacao", "--estado-dir", estado.toString(),
                "--pki-dir", pki.toString(), "--porta", String.valueOf(portaLivre()));

        assertThat(segundo.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(segundo.err()).contains("já está em execução").contains("PID " + pid);
        assertThat(ProcessHandle.of(pid).map(ProcessHandle::isAlive)).contains(true);
        assertThat(status().json().get("pid").asLong()).isEqualTo(pid);
    }

    @Test
    void shouldStopServerAndCleanState() {
        long pid = iniciar().json().get("pid").asLong();

        Resultado resultado = Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir", estado.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.json().get("estado").asText()).isEqualTo("PARADO");
        assertThat(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)).isFalse();
        assertThat(arquivoDeEstado()).doesNotExist();
        assertThat(status().json().get("estado").asText()).isEqualTo("PARADO");
    }

    @Test
    void shouldCleanOrphanStateWhenProcessIsDead() throws Exception {
        Process encerrado = new ProcessBuilder(ProcessHandle.current().info().command().orElseThrow(), "-version")
                .redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD).start();
        encerrado.waitFor();
        Files.createDirectories(arquivoDeEstado().getParent());
        Properties orfao = new Properties();
        orfao.setProperty("pid", String.valueOf(encerrado.pid()));
        orfao.setProperty("porta", String.valueOf(porta));
        orfao.setProperty("modo", "simulacao");
        try (OutputStream saida = Files.newOutputStream(arquivoDeEstado())) {
            orfao.store(saida, null);
        }

        Resultado resultado = status();
        Resultado parar = Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir", estado.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.json().get("estado").asText()).isEqualTo("PARADO");
        assertThat(resultado.err()).contains("órfão");
        assertThat(arquivoDeEstado()).doesNotExist();
        assertThat(parar.saida()).isZero();
    }

    @Test
    void shouldKillChildWhenReadinessTimesOut() {
        Resultado resultado = iniciar("--timeout", "1");

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
        assertThat(resultado.err()).contains("não ficou pronto");
        assertThat(pids).hasSize(1);
        await().atMost(Duration.ofSeconds(15))
                .until(() -> !ProcessHandle.of(pids.getFirst()).map(ProcessHandle::isAlive).orElse(false));
        assertThat(arquivoDeEstado()).doesNotExist();
    }

    @Test
    void shouldStopServerAfterIdleTimeout() {
        long pid = iniciar("--ociosidade", "2s").json().get("pid").asLong();

        await().atMost(Duration.ofSeconds(30))
                .until(() -> !ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false));

        assertThat(status().json().get("estado").asText()).isEqualTo("PARADO");
        assertThat(arquivoDeEstado()).doesNotExist();
    }

    private int prontidao() throws Exception {
        try (HttpClient cliente = HttpClient.newHttpClient()) {
            return cliente.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta
                    + "/actuator/health/readiness")).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        }
    }

    static int portaLivre() {
        try (ServerSocket socket = new ServerSocket(0, 0, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
