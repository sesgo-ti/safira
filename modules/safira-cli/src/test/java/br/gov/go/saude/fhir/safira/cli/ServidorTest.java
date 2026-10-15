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
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
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
        servidoresFilhos().forEach(ProcessHandle::destroyForcibly);
    }

    /** Filhos vivos deste processo de teste que rodam {@code servidor executar}. */
    private static List<ProcessHandle> servidoresFilhos() {
        return ProcessHandle.current().descendants().filter(ProcessHandle::isAlive)
                .filter(filho -> filho.info().arguments().map(List::of).orElse(List.of()).contains("executar"))
                .toList();
    }

    private Resultado iniciar(String... extras) {
        List<String> argumentos = new ArrayList<>(List.of("servidor", "iniciar", "--modo", "simulacao",
                "--estado-dir", estado.toString(), "--pki-dir", pki.toString(), "--porta", String.valueOf(porta)));
        argumentos.addAll(List.of(extras));
        if (!argumentos.contains("--ociosidade")) {
            // rede de segurança: um filho que escape da limpeza termina sozinho
            argumentos.addAll(List.of("--ociosidade", "5m"));
        }
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
        Optional<InetAddress> externo = enderecoNaoLoopback();
        if (externo.isPresent()) {
            try (Socket socket = new Socket()) {
                assertThatThrownBy(() -> socket.connect(new InetSocketAddress(externo.get(), porta), 2000))
                        .isInstanceOf(IOException.class);
            }
        }
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
    void shouldKeepActuatorOnLoopbackServerWhenConfigSetsManagementPort() throws Exception {
        int gerencia = portaLivre();
        Path config = Cli.escrever(diretorio.resolve("extra.yml"), "management:\n  server:\n    port: " + gerencia + "\n");

        Resultado resultado = iniciar("--config", config.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(prontidao()).isEqualTo(200);
        try (Socket socket = new Socket()) {
            assertThatThrownBy(() -> socket.connect(new InetSocketAddress(InetAddress.getLoopbackAddress(), gerencia), 2000))
                    .isInstanceOf(IOException.class);
        }
    }

    @Test
    void shouldExposeOnlyHealthEvenWhenConfigOpensAllActuatorEndpoints() throws Exception {
        Path config = Cli.escrever(diretorio.resolve("exposto.yml"), """
                management:
                  endpoints:
                    web:
                      exposure:
                        include: "*"
                  endpoint:
                    env:
                      enabled: true
                      show-values: always
                """);

        Resultado resultado = iniciar("--config", config.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(prontidao()).isEqualTo(200);
        assertThat(statusHttp("/actuator/env")).isEqualTo(404);
        assertThat(statusHttp("/actuator/beans")).isEqualTo(404);
        assertThat(statusHttp("/actuator/configprops")).isEqualTo(404);
    }

    @Test
    void shouldReportStartupFailureWithoutStackTrace() throws Exception {
        Path config = Cli.escrever(diretorio.resolve("gerencia.yml"), "management:\n  server:\n    address: 0.0.0.0\n");

        Resultado resultado = iniciar("--config", config.toString());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.err()).contains("terminou durante a partida").contains("servidor.log")
                .doesNotContain("\tat ").doesNotContain("Exception");
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
    void shouldDiscardCorruptedStateAsOrphanWithoutKillingAnyProcess() throws Exception {
        Process alheio = new ProcessBuilder("sleep", "60").start();
        try {
            Files.createDirectories(arquivoDeEstado().getParent());
            List<Resultado> resultados = new ArrayList<>();
            for (String comando : List.of("status", "parar", "iniciar")) {
                // ilegível: pid de um processo vivo, mas modo e porta corrompidos
                Files.writeString(arquivoDeEstado(), "pid=" + alheio.pid() + "\nmodo=\u0000lixo\nporta=abc\n");
                resultados.add(switch (comando) {
                    case "status" -> status();
                    case "parar" -> Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir",
                            estado.toString());
                    default -> iniciar();
                });
                assertThat(alheio.isAlive()).isTrue();
            }

            assertThat(resultados).allSatisfy(resultado -> {
                assertThat(resultado.saida()).isZero();
                assertThat(resultado.err()).contains("AVISO").contains("ilegível").contains("removido");
            });
            assertThat(resultados.get(0).json().get("estado").asText()).isEqualTo("PARADO");
            assertThat(resultados.get(2).json().get("estado").asText()).isEqualTo("UP");
        } finally {
            alheio.destroyForcibly();
        }
    }

    @Test
    void shouldNotKillReusedPidWhenProcessStartIsUnknown() throws Exception {
        Process alheio = new ProcessBuilder("sleep", "60").start();
        try {
            gravarEstado(alheio.pid(), null);

            Resultado parar = Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir", estado.toString());

            assertThat(parar.saida()).isZero();
            assertThat(parar.err()).contains("órfão").contains("não foi encerrado");
            assertThat(alheio.isAlive()).isTrue();
            assertThat(arquivoDeEstado()).doesNotExist();
        } finally {
            alheio.destroyForcibly();
        }
    }

    @Test
    void shouldNotKillProcessWhoseCommandIsNotTheServer() throws Exception {
        Process alheio = new ProcessBuilder("sleep", "60").start();
        try {
            gravarEstado(alheio.pid(), alheio.info().startInstant().orElseThrow());

            Resultado parar = Cli.executar("servidor", "parar", "--modo", "simulacao", "--estado-dir", estado.toString());
            Resultado segundo = iniciar();

            assertThat(parar.saida()).isZero();
            assertThat(parar.err()).contains("não foi encerrado");
            assertThat(alheio.isAlive()).isTrue();
            assertThat(segundo.saida()).isZero();
        } finally {
            alheio.destroyForcibly();
        }
    }

    private void gravarEstado(long pid, Instant inicio) throws IOException {
        Files.createDirectories(arquivoDeEstado().getParent());
        Properties gravado = new Properties();
        gravado.setProperty("pid", String.valueOf(pid));
        gravado.setProperty("porta", String.valueOf(porta));
        gravado.setProperty("modo", "simulacao");
        if (inicio != null) {
            gravado.setProperty("inicioDoProcesso", inicio.toString());
        }
        try (OutputStream saida = Files.newOutputStream(arquivoDeEstado())) {
            gravado.store(saida, null);
        }
    }

    @Test
    void shouldKillChildWhenStateCannotBeWritten() throws Exception {
        // o temporário da gravação atômica é um diretório não vazio: gravar o estado falha depois do fork
        Files.createDirectories(estado.resolve("simulacao").resolve("servidor.properties.tmp").resolve("bloqueio"));

        Resultado resultado = iniciar();

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.ERRO_INTERNO);
        assertThat(resultado.err()).contains("processo encerrado");
        await().atMost(Duration.ofSeconds(15)).until(() -> servidoresFilhos().isEmpty());
        assertThat(arquivoDeEstado()).doesNotExist();
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

    private int statusHttp(String caminho) throws Exception {
        try (HttpClient cliente = HttpClient.newHttpClient()) {
            return cliente.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta + caminho)).build(),
                    HttpResponse.BodyHandlers.discarding()).statusCode();
        }
    }

    private int prontidao() throws Exception {
        try (HttpClient cliente = HttpClient.newHttpClient()) {
            return cliente.send(HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + porta
                    + "/actuator/health/readiness")).build(), HttpResponse.BodyHandlers.discarding()).statusCode();
        }
    }

    /** Um endereço IPv4 da máquina fora do loopback (ausente em máquinas sem interface de rede ativa). */
    private static Optional<InetAddress> enderecoNaoLoopback() throws SocketException {
        return NetworkInterface.networkInterfaces().filter(ServidorTest::ativa)
                .flatMap(NetworkInterface::inetAddresses)
                .filter(endereco -> endereco instanceof Inet4Address && !endereco.isLoopbackAddress()
                        && !endereco.isLinkLocalAddress())
                .findFirst();
    }

    private static boolean ativa(NetworkInterface interfaceDeRede) {
        try {
            return interfaceDeRede.isUp() && !interfaceDeRede.isLoopback();
        } catch (SocketException e) {
            return false;
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
