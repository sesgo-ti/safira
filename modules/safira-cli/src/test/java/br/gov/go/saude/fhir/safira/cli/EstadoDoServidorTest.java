/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Identidade do processo do estado (contra PID reaproveitado) a partir do que o SO informa: no Windows
 * o JDK não fornece os argumentos; no Linux, com linha de comando longa, também não (só a linha truncada).
 */
class EstadoDoServidorTest {

    private static final Instant INICIO = Instant.parse("2026-10-22T10:15:30.250Z");
    private static final String JAVA = "/opt/java/openjdk/bin/java";
    private static final String[] SERVIDOR = {"-cp", "x.jar", "br.gov.go.saude.fhir.safira.cli.SafiraCli",
            "servidor", "executar", "--modo", "simulacao", "--porta", "8081"};

    @TempDir
    Path diretorio;

    private static EstadoDoServidor estado(Instant inicio, String comando) {
        return new EstadoDoServidor(Modo.SIMULACAO, 4242, 8081, inicio, comando, INICIO, null);
    }

    @Test
    void shouldConfirmIdentityWhenStartAndExecutableMatchWithoutArguments() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA), Optional.empty()))
                .isTrue();
    }

    @Test
    void shouldConfirmIdentityWhenStartDiffersOnlyBelowOneSecond() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(Instant.parse("2026-10-22T10:15:30.900Z")),
                Optional.of(JAVA), Optional.empty())).isTrue();
    }

    @Test
    void shouldConfirmIdentityWhenArgumentsAreTheServerInSameMode() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA),
                Optional.of(SERVIDOR))).isTrue();
    }

    @Test
    void shouldNotConfirmIdentityWhenArgumentsAreNotTheServer() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA),
                Optional.of(new String[] {"-jar", "outro.jar"}))).isFalse();
    }

    @Test
    void shouldNotConfirmIdentityWhenArgumentsAreServerOfAnotherMode() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA),
                Optional.of(new String[] {"servidor", "executar", "--modo", "icpbrasil"}))).isFalse();
    }

    @Test
    void shouldNotConfirmIdentityWhenStartDiffers() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO.plusSeconds(1)), Optional.of(JAVA),
                Optional.empty())).isFalse();
    }

    @Test
    void shouldNotConfirmIdentityWhenExecutableDiffers() {
        assertThat(estado(INICIO, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of("/usr/bin/sleep"),
                Optional.empty())).isFalse();
    }

    @Test
    void shouldNotConfirmIdentityWhenSystemDoesNotReportStartOrExecutable() {
        EstadoDoServidor estado = estado(INICIO, JAVA);

        assertThat(estado.identidadeConfirmada(Optional.empty(), Optional.of(JAVA), Optional.of(SERVIDOR))).isFalse();
        assertThat(estado.identidadeConfirmada(Optional.of(INICIO), Optional.empty(), Optional.of(SERVIDOR))).isFalse();
    }

    @Test
    void shouldNotConfirmIdentityWhenStateLacksStartOrExecutable() {
        assertThat(estado(null, JAVA).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA),
                Optional.of(SERVIDOR))).isFalse();
        assertThat(estado(INICIO, null).identidadeConfirmada(Optional.of(INICIO), Optional.of(JAVA),
                Optional.of(SERVIDOR))).isFalse();
    }

    @Test
    void shouldKeepExecutableWhenStateIsWrittenAndRead() {
        estado(INICIO, JAVA).gravar(diretorio);

        assertThat(EstadoDoServidor.ler(diretorio)).hasValueSatisfying(lido -> {
            assertThat(lido.comando()).isEqualTo(JAVA);
            assertThat(lido.inicioDoProcesso()).isEqualTo(INICIO);
        });
    }
}
