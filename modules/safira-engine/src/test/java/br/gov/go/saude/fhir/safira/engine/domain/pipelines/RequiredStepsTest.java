/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RequiredStepsTest {

    private static final PipelineKey VALIDATION = new PipelineKey("politica|0.2.0", OperationType.VALIDATION);
    private static final RequiredSteps REQUIRED = new RequiredSteps(VALIDATION, List.of("a", "dss", "outcome"));

    private static PipelineDefinition definition(String... steps) {
        return new PipelineDefinition(VALIDATION, List.of(steps));
    }

    @Test
    void shouldAcceptPipelineWithAllRequiredStepsInOrder() {
        assertThatCode(() -> RequiredSteps.verificar(List.of(definition("a", "dss", "outcome")), List.of(REQUIRED)))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldAcceptExtraStepsBetweenRequiredOnes() {
        assertThatCode(() -> RequiredSteps.verificar(List.of(definition("a", "extra", "dss", "outcome")), List.of(REQUIRED)))
                .doesNotThrowAnyException();
    }

    @Test
    void shouldRejectPipelineMissingRequiredStep() {
        assertThatThrownBy(() -> RequiredSteps.verificar(List.of(definition("a", "outcome")), List.of(REQUIRED)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("dss")
                .hasMessageContaining("politica|0.2.0");
    }

    @Test
    void shouldRejectPipelineWithRequiredStepsOutOfOrder() {
        assertThatThrownBy(() -> RequiredSteps.verificar(List.of(definition("a", "outcome", "dss")), List.of(REQUIRED)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("ordem");
    }

    @Test
    void shouldIgnoreRequirementForPipelineNotConfigured() {
        PipelineDefinition signing = new PipelineDefinition(new PipelineKey("politica|0.2.0", OperationType.SIGNING), List.of("x"));

        assertThatCode(() -> RequiredSteps.verificar(List.of(signing), List.of(REQUIRED))).doesNotThrowAnyException();
    }
}
