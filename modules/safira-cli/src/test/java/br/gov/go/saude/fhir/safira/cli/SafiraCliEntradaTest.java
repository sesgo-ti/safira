/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;

/** Erros de uso, entrada inválida e senha (Review Focus 5): saída 3, só JSON no stdout, sem stack trace. */
class SafiraCliEntradaTest {

    private static final String SEGREDO = "segredo-que-nao-pode-vazar";

    @TempDir
    Path diretorio;

    private Path pki;
    private Path bundle;
    private Path provenance;

    @BeforeEach
    void preparar() throws Exception {
        pki = diretorio.resolve("pki");
        bundle = Cli.exemplo(diretorio, "bundle.json");
        provenance = Cli.exemplo(diretorio, "provenance.json");
    }

    private Resultado validarSimulado(Path signature, Path bundleValidado, String... extras) {
        String[] base = {"validar", "--modo", "simulacao", "--pki-dir", pki.toString(),
                "--signature", signature.toString(), "--bundle", bundleValidado.toString(),
                "--provenance", provenance.toString()};
        String[] argumentos = new String[base.length + extras.length];
        System.arraycopy(base, 0, argumentos, 0, base.length);
        System.arraycopy(extras, 0, argumentos, base.length, extras.length);
        return Cli.executar(argumentos);
    }

    @Test
    void shouldExitWithThreeWhenInputIsNotJson() throws Exception {
        Path lixo = Cli.escrever(diretorio.resolve("lixo.json"), "isto não é JSON {");

        Resultado resultado = validarSimulado(lixo, bundle);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.codigo()).isEqualTo("FORMAT.JSON-MALFORMED");
        assertThat(resultado.out()).doesNotContain("Exception").doesNotContain("\tat ");
    }

    @Test
    void shouldExitWithThreeWhenInputIsJsonButNotAnObject() throws Exception {
        Path vetor = Cli.escrever(diretorio.resolve("vetor.json"), "[1, 2]");

        Resultado resultado = validarSimulado(vetor, bundle);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.codigo()).isEqualTo("FORMAT.JSON-MALFORMED");
    }

    @Test
    void shouldNotInjectMembersThroughInputFile() throws Exception {
        Path injetado = Cli.escrever(diretorio.resolve("injetado.json"), "{}, \"policyIdentifierUri\": \"x\"");

        Resultado resultado = validarSimulado(injetado, bundle);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.codigo()).isEqualTo("FORMAT.JSON-MALFORMED");
    }

    @Test
    void shouldExitWithThreeWhenBundleExceedsMaxBundleSize() throws Exception {
        Path config = Cli.escrever(diretorio.resolve("limite.yml"),
                "safira:\n  operational:\n    security:\n      max-bundle-size: 1048576\n");
        Path grande = Cli.escrever(diretorio.resolve("grande.json"),
                "{\"resourceType\":\"Bundle\",\"x\":\"" + "a".repeat(1_100_000) + "\"}");

        Resultado resultado = validarSimulado(bundle, grande, "--config", config.toString());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.codigo()).isEqualTo("SECURITY.BUNDLE-SIZE-LIMIT-EXCEEDED");
    }

    @Test
    void shouldExitWithThreeWhenInputFileIsMissing() {
        Resultado resultado = validarSimulado(diretorio.resolve("nao-existe.json"), bundle);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains("nao-existe.json");
    }

    @Test
    void shouldNotAcceptPasswordAsArgument() {
        Resultado resultado = Cli.executar("assinar", "--modo", "simulacao", "--bundle", bundle.toString(),
                "--provenance", provenance.toString(), "--p12", "a.p12", "--estrategia", "iat",
                "--senha", SEGREDO);
        Resultado comIgual = Cli.executar("assinar", "--modo", "simulacao", "--bundle", bundle.toString(),
                "--provenance", provenance.toString(), "--p12", "a.p12", "--estrategia", "iat",
                "--senha-arquivo", "s.txt", "--senha=" + SEGREDO);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(comIgual.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out() + resultado.err() + comIgual.out() + comIgual.err()).doesNotContain(SEGREDO);
        assertThat(SafiraCli.linhaDeComando().getSubcommands().get("assinar").getCommandSpec().findOption("--senha"))
                .isNull();
    }

    @Test
    void shouldRequireExactlyOnePasswordSource() {
        Resultado nenhuma = Cli.executar("assinar", "--modo", "simulacao", "--bundle", bundle.toString(),
                "--provenance", provenance.toString(), "--p12", "a.p12", "--estrategia", "iat");
        Resultado duas = Cli.executar("assinar", "--modo", "simulacao", "--bundle", bundle.toString(),
                "--provenance", provenance.toString(), "--p12", "a.p12", "--estrategia", "iat",
                "--senha-arquivo", "s.txt", "--senha-env", "SENHA");

        assertThat(nenhuma.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(duas.saida()).isEqualTo(CodigosDeSaida.USO);
    }

    @Test
    void shouldRejectPkiDirectoryOutsideSimulationMode() {
        Resultado resultado = Cli.executar("validar", "--modo", "icpbrasil", "--pki-dir", pki.toString(),
                "--signature", bundle.toString(), "--bundle", bundle.toString(), "--provenance", provenance.toString());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains("--pki-dir");
    }

    /** Executa com o stdout e o stderr reais do processo redirecionados para buffers. */
    private static Resultado comSaidasDoProcesso(Supplier<Resultado> execucao, ByteArrayOutputStream out,
                                                 ByteArrayOutputStream err) {
        PrintStream outOriginal = System.out;
        PrintStream errOriginal = System.err;
        try {
            System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
            System.setErr(new PrintStream(err, true, StandardCharsets.UTF_8));
            return execucao.get();
        } finally {
            System.setOut(outOriginal);
            System.setErr(errOriginal);
        }
    }

    @Test
    void shouldNeverWriteStackTraceToStdout() throws Exception {
        Files.createDirectories(pki);
        Cli.escrever(pki.resolve("pki.properties"), "corrompido");
        ByteArrayOutputStream stdoutDoProcesso = new ByteArrayOutputStream();

        Resultado resultado = comSaidasDoProcesso(() -> validarSimulado(bundle, bundle), stdoutDoProcesso,
                new ByteArrayOutputStream());
        Resultado detalhado = comSaidasDoProcesso(() -> validarSimulado(bundle, bundle, "--verbose"), stdoutDoProcesso,
                new ByteArrayOutputStream());

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains(pki.toString()).doesNotContain("\tat ");
        assertThat(detalhado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(detalhado.out()).isEmpty();
        assertThat(detalhado.err()).contains("\tat ");
        assertThat(stdoutDoProcesso.toString(StandardCharsets.UTF_8)).doesNotContain("\tat ").doesNotContain("Exception");
    }

    private String logDeErroComExcecao(boolean verbose) {
        ByteArrayOutputStream stderr = new ByteArrayOutputStream();
        comSaidasDoProcesso(() -> {
            try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.SIMULACAO, pki, null, verbose)) {
                LoggerFactory.getLogger(PipelineExecutor.class).error("Erro inesperado no step",
                        new IllegalArgumentException("causa interna"));
            }
            return null;
        }, new ByteArrayOutputStream(), stderr);
        return stderr.toString(StandardCharsets.UTF_8);
    }

    @Test
    void shouldLogOnlyShortMessageWithoutStackTraceWhenNotVerbose() {
        assertThat(logDeErroComExcecao(false)).contains("Erro inesperado no step").doesNotContain("\tat ")
                .doesNotContain("IllegalArgumentException");
        assertThat(logDeErroComExcecao(true)).contains("Erro inesperado no step").contains("\tat ");
        assertThat(logDeErroComExcecao(false)).doesNotContain("\tat ");
    }

    @Test
    void shouldSilenceSpringLogsOnStartupFailureWithoutVerbose() throws Exception {
        Path config = Cli.escrever(diretorio.resolve("misturado.yml"), """
                spring:
                  main:
                    sources: >-
                      br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration,
                      br.gov.go.saude.fhir.safira.app.icpbrasil.SafiraIcpBrasilAutoConfiguration
                """);
        ByteArrayOutputStream stderrDoProcesso = new ByteArrayOutputStream();
        ByteArrayOutputStream stderrDetalhado = new ByteArrayOutputStream();

        Resultado resultado = comSaidasDoProcesso(() -> validarSimulado(bundle, bundle, "--config", config.toString()),
                new ByteArrayOutputStream(), stderrDoProcesso);
        comSaidasDoProcesso(() -> validarSimulado(bundle, bundle, "--config", config.toString(), "--verbose"),
                new ByteArrayOutputStream(), stderrDetalhado);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.err()).startsWith("Erro: falha na partida");
        assertThat(stderrDoProcesso.toString(StandardCharsets.UTF_8)).doesNotContain("Exception encountered");
        assertThat(stderrDetalhado.toString(StandardCharsets.UTF_8)).contains("Exception encountered");
    }

    @Test
    void shouldNotEchoArgumentAfterUnknownOption() {
        Resultado resultado = Cli.executar("assinar", "--modo", "simulacao", "--bundle", bundle.toString(),
                "--provenance", provenance.toString(), "--p12", "a.p12", "--estrategia", "iat",
                "--senha-arquivo", "s.txt", "--senha", "-" + SEGREDO);

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out() + resultado.err()).doesNotContain(SEGREDO).contains("--senha");
    }

    @Test
    void shouldCheckInputFilesBeforeStartingSpring() {
        Resultado validacao = validarSimulado(diretorio.resolve("nao-existe.json"), bundle);
        Resultado assinatura = Cli.executar("assinar", "--modo", "simulacao", "--pki-dir", pki.toString(),
                "--bundle", bundle.toString(), "--provenance", provenance.toString(),
                "--p12", diretorio.resolve("nao-existe.p12").toString(), "--estrategia", "iat",
                "--senha-arquivo", diretorio.resolve("nao-existe.txt").toString());

        assertThat(validacao.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(assinatura.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(validacao.err() + assinatura.err()).doesNotContain(AvisoSimulacaoAdvice.TEXTO);
        assertThat(assinatura.err()).contains("nao-existe.p12");
        assertThat(pki).doesNotExist();
    }

    @Test
    void shouldRejectTrustTimeoutOutsideLibraryRange() {
        Resultado curto = Cli.executar("validar", "--timeout-acervo", "5", "--signature", bundle.toString(),
                "--bundle", bundle.toString(), "--provenance", provenance.toString());
        Resultado longo = Cli.executar("validar", "--timeout-acervo", "301", "--signature", bundle.toString(),
                "--bundle", bundle.toString(), "--provenance", provenance.toString());

        assertThat(curto.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(longo.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(curto.err()).contains("--timeout-acervo");
    }

    @Test
    void shouldRejectTrustTimeoutInSimulationMode() {
        Resultado resultado = validarSimulado(bundle, bundle, "--timeout-acervo", "30");

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.err()).contains("--timeout-acervo");
        assertThat(pki).doesNotExist();
    }

    @Test
    void shouldExitWithThreeOnUnknownMode() {
        Resultado resultado = Cli.executar("validar", "--modo", "outro", "--signature", "s.json",
                "--bundle", "b.json", "--provenance", "p.json");

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
    }
}
