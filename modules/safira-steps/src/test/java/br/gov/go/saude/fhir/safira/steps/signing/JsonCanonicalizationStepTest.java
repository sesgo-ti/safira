/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JsonCanonicalizationStepTest {

    private JsonCanonicalizationStep step;

    @BeforeEach
    void setUp() {
        step = new JsonCanonicalizationStep();
    }

    @Test
    void shouldCanonicalizeEachPreparedResource() {
        var context = contextWith(List.of(
                "{\"resourceType\":\"Patient\",\"name\":\"João\"}",
                "{\"resourceType\":\"Observation\",\"status\":\"final\"}"
        ));

        var result = step.execute(context);

        assertSuccess(result);
        assertEquals(2, canonicalizedResources(result).size());
    }

    @Test
    void shouldSortJsonKeysAlphabetically() {
        var context = contextWith(List.of("{\"z_field\":\"last\",\"a_field\":\"first\",\"m_field\":\"middle\"}"));

        var result = step.execute(context);

        assertSuccess(result);
        assertEquals("{\"a_field\":\"first\",\"m_field\":\"middle\",\"z_field\":\"last\"}",
                canonicalizedResources(result).getFirst());
    }

    @Test
    void shouldPreserveOrderOfResources() {
        var context = contextWith(List.of(
                "{\"resourceType\":\"Patient\"}",
                "{\"resourceType\":\"Observation\"}"
        ));

        var result = step.execute(context);

        assertSuccess(result);
        var canonicalized = canonicalizedResources(result);
        assertTrue(canonicalized.get(0).contains("Patient"));
        assertTrue(canonicalized.get(1).contains("Observation"));
    }

    @Test
    void shouldThrowStepExceptionWhenPreparedResourcesNotFound() {
        SigningContext context = SigningContext.builder().build();
        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(List<String> preparedResources) {
        return SigningContext.builder()
                .attribute(PayloadPreparationStep.PREPARED_RESOURCES_KEY, preparedResources)
                .build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    @SuppressWarnings("unchecked")
    private List<String> canonicalizedResources(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(JsonCanonicalizationStep.CANONICALIZED_RESOURCES_KEY, List.class).orElseThrow();
    }
}
