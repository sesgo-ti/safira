/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

/** {@code safira assinar|validar --modo simulacao} sobre a PKI simulada persistida (gerada na 1ª execução). */
class SafiraCliSimulacaoTest {

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

    private Resultado assinar(String... extras) {
        String[] base = {"assinar", "--modo", "simulacao", "--pki-dir", pki.toString(),
                "--bundle", bundle.toString(), "--provenance", provenance.toString(),
                "--p12", pki.resolve("signatario.p12").toString(), "--alias", "signatario",
                "--estrategia", "iat"};
        String[] argumentos = new String[base.length + extras.length];
        System.arraycopy(base, 0, argumentos, 0, base.length);
        System.arraycopy(extras, 0, argumentos, base.length, extras.length);
        return Cli.executar(argumentos);
    }

    private Resultado validar(JsonNode assinada, Path bundleValidado) throws Exception {
        Path signature = Cli.escrever(diretorio.resolve("signature.json"), assinada.get("signature").toString());
        Path provenanceFinal = Cli.escrever(diretorio.resolve("provenance-final.json"), assinada.get("provenance").toString());
        return Cli.executar("validar", "--modo", "simulacao", "--pki-dir", pki.toString(),
                "--signature", signature.toString(), "--bundle", bundleValidado.toString(),
                "--provenance", provenanceFinal.toString());
    }

    @Test
    void shouldSignAndValidateWithSimulatedPki() throws Exception {
        Resultado assinada = assinar("--senha-arquivo", pki.resolve("senha.txt").toString());

        assertThat(assinada.saida()).isEqualTo(CodigosDeSaida.SUCESSO);
        assertThat(assinada.json().get("signature").get("data").asText()).isNotEmpty();
        assertThat(assinada.json().get("provenance").get("resourceType").asText()).isEqualTo("Provenance");

        Resultado validada = validar(assinada.json(), bundle);

        assertThat(validada.saida()).isEqualTo(CodigosDeSaida.SUCESSO);
        assertThat(validada.codigo()).isEqualTo("VALIDATION.SUCCESS");
    }

    @Test
    void shouldMarkOutputInSimulationMode() throws Exception {
        Resultado assinada = assinar("--senha-arquivo", pki.resolve("senha.txt").toString());
        Resultado validada = validar(assinada.json(), bundle);

        assertThat(assinada.json().get("simulacao").asText()).isEqualTo(AvisoSimulacaoAdvice.TEXTO);
        assertThat(assinada.err()).contains(AvisoSimulacaoAdvice.TEXTO);
        assertThat(validada.out()).contains(AvisoSimulacaoAdvice.TEXTO);
        assertThat(validada.err()).contains(AvisoSimulacaoAdvice.TEXTO);
    }

    @Test
    void shouldExitWithSixWhenSignatureIsTampered() throws Exception {
        Resultado assinada = assinar("--senha-arquivo", pki.resolve("senha.txt").toString());
        String original = Files.readString(bundle);
        Path alterado = Cli.escrever(diretorio.resolve("bundle-alterado.json"),
                original.replace("\"Souza\"", "\"Souza-Alterada\""));
        assertThat(alterado).content().isNotEqualTo(original);

        Resultado validada = validar(assinada.json(), alterado);

        assertThat(validada.saida()).isEqualTo(CodigosDeSaida.REPROVADA);
        assertThat(validada.json().get("resourceType").asText()).isEqualTo("OperationOutcome");
        assertThat(validada.out()).doesNotContain(AvisoSimulacaoAdvice.TEXTO);
    }

    @Test
    void shouldWriteResultToOutputFileAndKeepStdoutEmpty() throws Exception {
        Path saida = diretorio.resolve("assinada.json");

        Resultado assinada = assinar("--senha-arquivo", pki.resolve("senha.txt").toString(), "--saida", saida.toString());

        assertThat(assinada.saida()).isEqualTo(CodigosDeSaida.SUCESSO);
        assertThat(assinada.out()).isEmpty();
        assertThat(saida).content().contains("\"signature\"");
    }

    @Test
    void shouldReadPasswordFromStdin() throws Exception {
        Cli.executar("validar", "--modo", "simulacao", "--pki-dir", pki.toString(), "--signature", bundle.toString(),
                "--bundle", bundle.toString(), "--provenance", provenance.toString());
        InputStream original = System.in;
        try {
            System.setIn(new ByteArrayInputStream((Files.readString(pki.resolve("senha.txt")).strip() + "\n")
                    .getBytes(StandardCharsets.UTF_8)));

            assertThat(assinar("--senha-stdin").saida()).isEqualTo(CodigosDeSaida.SUCESSO);
        } finally {
            System.setIn(original);
        }
    }
}
