/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class PayloadValidationStepTest {

    private static final String U1 = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6";

    private static SigningContext context(String targetReference) {
        return SigningContext.builder()
                .bundleJson(LosslessJson.parseObject("{\"resourceType\":\"Bundle\",\"entry\":[{\"fullUrl\":\"" + U1
                        + "\",\"resource\":{\"resourceType\":\"Patient\"}}]}"))
                .provenanceJson(LosslessJson.parseObject("{\"resourceType\":\"Provenance\",\"target\":[{\"reference\":\""
                        + targetReference + "\"}]}"))
                .operationalConfig(TestConfigs.operational())
                .build();
    }

    @Test
    void shouldAcceptConformingContent() {
        assertThat(new PayloadValidationStep().execute(context(U1)).isSuccess()).isTrue();
    }

    @Test
    void shouldReportContentRuleViolation() {
        StepResult<SigningContext> result = new PayloadValidationStep().execute(context(U1.toUpperCase()));

        assertThat(result).isInstanceOf(StepResult.Failure.class);
        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_INVALID);
    }

    @Test
    void shouldRejectMissingBundle() {
        SigningContext context = context(U1).toBuilder().bundleJson(null).build();

        StepResult<SigningContext> result = new PayloadValidationStep().execute(context);

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }
}
