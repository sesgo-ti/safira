/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.rest.dto.ValidationInput;
import br.gov.go.saude.fhir.safira.rest.mapper.ValidationInputMapper;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ValidationServiceTest {

    @Test
    void shouldInvokeExecutorValidateWithMappedContext() {
        PipelineExecutor executor = mock(PipelineExecutor.class);
        ValidationInputMapper mapper = mock(ValidationInputMapper.class);

        String policyUri = "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";
        ValidationInput input = new ValidationInput(
                "signed-base64",
                1751328000L,
                policyUri,
                null,
                null
        );

        ValidationContext mappedContext = ValidationContext.builder()
                .signedDataBase64("signed-base64")
                .referenceTimestamp(1751328000L)
                .policyIdentifierUri(policyUri)
                .build();

        OperationOutcome outcome = OperationOutcome.createSignatureError(
                "information", "informational", "VALIDATION_SUCCESS", "ok", null);
        PipelineResult<OperationOutcome> expectedResult = new PipelineResult.Success<>(outcome);

        when(mapper.toContext(input)).thenReturn(mappedContext);
        when(executor.validate(eq(policyUri), any(ValidationContext.class))).thenReturn(expectedResult);

        ValidationService service = new ValidationService(executor, mapper);

        PipelineResult<OperationOutcome> result = service.validate(input);

        assertSame(expectedResult, result);

        ArgumentCaptor<ValidationContext> captor = ArgumentCaptor.forClass(ValidationContext.class);
        verify(executor).validate(eq(policyUri), captor.capture());
        assertSame(mappedContext, captor.getValue());
        assertEquals("signed-base64", captor.getValue().getSignedDataBase64());
    }
}
