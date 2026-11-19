/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code safira simulador pki}: caminhos e allowlist da PKI simulada persistida, nunca a senha. */
class SimuladorPkiTest {

    @TempDir
    Path diretorio;

    @Test
    void shouldPrintSimulatedPkiWithoutPassword() throws Exception {
        Path pki = diretorio.resolve("pki");

        Resultado resultado = Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

        assertThat(resultado.saida()).isZero();
        JsonNode json = resultado.json();
        assertThat(json.get("diretorio").asText()).isEqualTo(pki.toAbsolutePath().toString());
        assertThat(json.get("signatario").asText()).isEqualTo(pki.resolve("signatario.p12").toAbsolutePath().toString());
        assertThat(json.get("alias").asText()).isEqualTo("signatario");
        assertThat(json.get("senha").asText()).isEqualTo(pki.resolve("senha.txt").toAbsolutePath().toString());
        assertThat(json.get("issuerSha256").asText()).matches("[0-9a-f]{64}");
        assertThat(json.get("situacao").asText()).isEqualTo("GERADA");
        assertThat(resultado.out()).doesNotContain(Files.readString(pki.resolve("senha.txt")).strip());
        assertThat(resultado.err()).contains("SIMULAÇÃO");
    }

    @Test
    void shouldMentionPkiDirOptionWhenPkiIsInUse() throws Exception {
        Path pki = diretorio.resolve("pki");
        Path trava = pki.resolveSibling("pki.lock");
        try (FileChannel canal = FileChannel.open(trava, StandardOpenOption.CREATE, StandardOpenOption.WRITE);
             FileLock ignorada = canal.lock()) {
            Resultado resultado = Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

            assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
            assertThat(resultado.err()).contains("em uso").contains("--pki-dir");
        }
    }

    @Test
    void shouldReuseSimulatedPkiOnSecondCall() {
        Path pki = diretorio.resolve("pki");
        Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

        Resultado resultado = Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.json().get("situacao").asText()).isEqualTo("REUTILIZADA");
    }

    @Test
    void shouldWriteStdoutAsUtf8WhenConsoleEncodingIsNotUtf8() throws Exception {
        Path pki = diretorio.resolve("pki");
        Path saida = diretorio.resolve("latin1.json");
        Process processo = simuladorPkiEmProcesso(pki, saida, "-Dstdout.encoding=ISO-8859-1");
        assertThat(processo.waitFor(60, TimeUnit.SECONDS)).isTrue();

        String json = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(Files.readAllBytes(saida))).toString();

        assertThat(processo.exitValue()).isZero();
        assertThat(json).contains("SIMULAÇÃO");
    }

    /**
     * {@code safira simulador pki} num processo próprio (travas de arquivo valem entre processos): stdout em
     * {@code saida} e stderr em {@code saida.err}.
     */
    private static Process simuladorPkiEmProcesso(Path pki, Path saida, String... opcoesDaJvm) throws Exception {
        String java = ProcessHandle.current().info().command().orElse(Path.of(System.getProperty("java.home"), "bin",
                "java").toString());
        String classpath = GerenciadorDoServidor.classpathEmArquivo(saida.resolveSibling(saida.getFileName() + ".args"),
                System.getProperty("java.class.path"));
        List<String> comando = new ArrayList<>(List.of(java));
        comando.addAll(List.of(opcoesDaJvm));
        comando.addAll(List.of(classpath, SafiraCli.class.getName(), "simulador", "pki", "--pki-dir", pki.toString()));
        return new ProcessBuilder(comando)
                .redirectOutput(saida.toFile())
                .redirectError(erros(saida).toFile())
                .start();
    }

    private static Path erros(Path saida) {
        return saida.resolveSibling(saida.getFileName() + ".err");
    }

    /** stdout (UTF-8) e stderr (codificação do console) do processo. */
    private static String textos(Path saida) throws Exception {
        return Files.readString(saida, StandardCharsets.UTF_8)
                + Files.readString(erros(saida), Charset.forName(System.getProperty("native.encoding")));
    }

    @Test
    void shouldLetParallelReadersShareExistingPki() throws Exception {
        Path pki = diretorio.resolve("pki");
        assertThat(Cli.executar("simulador", "pki", "--pki-dir", pki.toString()).saida()).isZero();
        List<Process> processos = new ArrayList<>();
        List<Path> saidas = new ArrayList<>();
        try {
            for (int i = 0; i < 5; i++) {
                Path saida = diretorio.resolve("saida-" + i + ".txt");
                saidas.add(saida);
                processos.add(simuladorPkiEmProcesso(pki, saida));
            }
            List<Integer> codigos = new ArrayList<>();
            for (Process processo : processos) {
                assertThat(processo.waitFor(60, TimeUnit.SECONDS)).isTrue();
                codigos.add(processo.exitValue());
            }
            List<String> textos = new ArrayList<>();
            for (Path saida : saidas) {
                textos.add(textos(saida));
            }

            assertThat(textos).allSatisfy(texto -> assertThat(texto).doesNotContain("em uso"));
            assertThat(codigos).containsOnly(0);
        } finally {
            processos.forEach(Process::destroyForcibly);
        }
    }

    @Test
    void shouldLetParallelProcessesWaitWhenFirstGenerationIsInProgress() throws Exception {
        Path pki = diretorio.resolve("pki");
        List<Process> processos = new ArrayList<>();
        List<Path> saidas = new ArrayList<>();
        try {
            for (int i = 0; i < 4; i++) {
                Path saida = diretorio.resolve("geracao-" + i + ".txt");
                saidas.add(saida);
                processos.add(simuladorPkiEmProcesso(pki, saida));
            }
            List<Integer> codigos = new ArrayList<>();
            for (Process processo : processos) {
                assertThat(processo.waitFor(60, TimeUnit.SECONDS)).isTrue();
                codigos.add(processo.exitValue());
            }
            StringBuilder textos = new StringBuilder();
            for (Path saida : saidas) {
                textos.append(textos(saida));
            }

            assertThat(textos.toString()).doesNotContain("em uso").containsOnlyOnce("\"GERADA\"");
            assertThat(codigos).containsOnly(0);
        } finally {
            processos.forEach(Process::destroyForcibly);
        }
    }
}
