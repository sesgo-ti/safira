/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ValidationServiceTest {

    private static final String POLICY = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";
    private static final SafiraOperationalConfigProperties OPS =
            new SafiraOperationalConfigProperties(null, null, null, null, null);

    @Test
    void shouldRunSinglePolicyPipelineWithLosslessContext() {
        PipelineExecutor executor = mock(PipelineExecutor.class);
        PipelineResult<OperationOutcome> expected = new PipelineResult.Success<>(
                OperationOutcome.createSignatureError("information", "informational", "VALIDATION.SUCCESS", "ok", null));
        when(executor.validate(eq(POLICY), any(ValidationContext.class))).thenReturn(expected);
        String body = "{\"signature\":{\"data\":\"eA==\"},\"bundle\":{\"resourceType\":\"Bundle\",\"n\":1.10},"
                + "\"provenance\":{\"resourceType\":\"Provenance\"},\"referenceTimestamp\":1790000000,"
                + "\"policyIdentifierUri\":\"https://outra/politica/9.9.9\"}";

        PipelineResult<OperationOutcome> result = new ValidationService(executor, OPS).validate(body);

        assertThat(result).isSameAs(expected);
        ArgumentCaptor<ValidationContext> captor = ArgumentCaptor.forClass(ValidationContext.class);
        verify(executor).validate(eq(POLICY), captor.capture());
        ValidationContext context = captor.getValue();
        assertThat(LosslessJson.write(context.getBundleJson())).isEqualTo("{\"resourceType\":\"Bundle\",\"n\":1.10}");
        assertThat(context.getPolicyIdentifierUri()).isEqualTo("https://outra/politica/9.9.9");
        assertThat(context.getReferenceTimestamp()).isEqualTo(1790000000L);
        assertThat(context.getOperationalConfig()).isSameAs(OPS);
    }

    @Test
    void shouldReturnFailureWithoutRunningPipelineForMalformedBody() {
        PipelineExecutor executor = mock(PipelineExecutor.class);

        PipelineResult<OperationOutcome> result = new ValidationService(executor, OPS).validate("{\"signature\":[]}");

        assertThat(result.getExceptionDetails().issue().getFirst().details().coding().getFirst().code())
                .isEqualTo("FORMAT.SIGNATURE-MISSING");
        verify(executor, never()).validate(anyString(), any());
    }
}
