/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ValidarTest {

    private static final OperationOutcome SUCESSO = OperationOutcome.createSignatureError("information",
            "informational", "VALIDATION.SUCCESS", "Assinatura digital validada com sucesso", "diagnóstico");

    @Test
    void shouldExitWithSuccessOnlyWhenPipelineSucceeded() {
        assertThat(Validar.saida(new PipelineResult.Success<>(SUCESSO))).isEqualTo(CodigosDeSaida.SUCESSO);
    }

    @Test
    void shouldNotExitWithSuccessWhenPipelineFailedWithSuccessCode() {
        assertThat(Validar.saida(new PipelineResult.Failure<>(SUCESSO))).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }

    @Test
    void shouldNotExitWithSuccessWhenOutcomeIsMissing() {
        assertThat(Validar.saida(new PipelineResult.Success<>(null))).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
        assertThat(Validar.saida(new PipelineResult.Failure<>(null))).isEqualTo(CodigosDeSaida.INCONCLUSIVO);
    }
}
