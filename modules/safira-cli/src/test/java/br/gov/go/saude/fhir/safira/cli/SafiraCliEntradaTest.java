/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

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

    @Test
    void shouldNeverWriteStackTraceToStdout() throws Exception {
        Files.createDirectories(pki);
        Cli.escrever(pki.resolve("pki.properties"), "corrompido");

        Resultado resultado = validarSimulado(bundle, bundle);
        Resultado detalhado = validarSimulado(bundle, bundle, "--verbose");

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains(pki.toString()).doesNotContain("\tat ");
        assertThat(detalhado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(detalhado.out()).isEmpty();
        assertThat(detalhado.err()).contains("\tat ");
    }

    @Test
    void shouldExitWithThreeOnUnknownMode() {
        Resultado resultado = Cli.executar("validar", "--modo", "outro", "--signature", "s.json",
                "--bundle", "b.json", "--provenance", "p.json");

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
    }
}
