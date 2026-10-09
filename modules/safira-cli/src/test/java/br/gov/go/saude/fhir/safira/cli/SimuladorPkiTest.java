/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import com.fasterxml.jackson.databind.JsonNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

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
    void shouldReuseSimulatedPkiOnSecondCall() {
        Path pki = diretorio.resolve("pki");
        Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

        Resultado resultado = Cli.executar("simulador", "pki", "--pki-dir", pki.toString());

        assertThat(resultado.saida()).isZero();
        assertThat(resultado.json().get("situacao").asText()).isEqualTo("REUTILIZADA");
    }
}
