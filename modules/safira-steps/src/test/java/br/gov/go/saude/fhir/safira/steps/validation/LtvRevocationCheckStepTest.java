/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class LtvRevocationCheckStepTest {

    private LtvRevocationCheckStep step;

    @BeforeEach
    void setUp() {
        step = new LtvRevocationCheckStep();
    }

    @Test
    void shouldAppendStubWarningAndReturnSuccess() {
        Map<String, Object> unprotected = new LinkedHashMap<>();
        unprotected.put("rRefs", new LinkedHashMap<>());
        ValidationContext context = ValidationContext.builder()
                .unprotectedHeader(unprotected)
                .warnings(new ArrayList<>())
                .build();

        StepResult<ValidationContext> result = step.execute(context);

        StepResult.Success<ValidationContext> success = assertInstanceOf(StepResult.Success.class, result);
        List<OperationOutcome.Issue> warnings = success.context().getWarnings();
        assertEquals(1, warnings.size());
        OperationOutcome.Issue issue = warnings.get(0);
        assertEquals("warning", issue.severity());
        assertEquals("business-rule", issue.code());
        assertEquals(SignatureExceptionCode.REVOCATION.getCode(),
                issue.details().coding().get(0).code());
        assertTrue(issue.diagnostics().contains("Verificação completa de revogação"));
    }

    @Test
    void shouldReturnSuccessEvenWithEmptyUnprotectedHeader() {
        ValidationContext context = ValidationContext.builder()
                .warnings(new ArrayList<>())
                .build();

        StepResult<ValidationContext> result = step.execute(context);

        StepResult.Success<ValidationContext> success = assertInstanceOf(StepResult.Success.class, result);
        assertEquals(1, success.context().getWarnings().size());
    }
}
