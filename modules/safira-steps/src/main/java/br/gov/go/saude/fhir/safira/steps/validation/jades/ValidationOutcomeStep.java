/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;

import java.time.Instant;

/**
 * Passo {@code validation-outcome}: seção 8 do caso de uso de validação — {@code OperationOutcome}
 * de sucesso ({@code information}/{@code informational}, {@code VALIDATION.SUCCESS}) que distingue
 * assinatura de pessoa física (A3/A4) de selo de pessoa jurídica (SE-S/SE-H), sem dados sensíveis.
 */
@StepId("validation-outcome")
public class ValidationOutcomeStep implements ValidationStep {

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        SignerIdentity identity = context.getAttribute(ValidationKeys.SIGNER_IDENTITY, SignerIdentity.class).orElseThrow();
        JadesLevel level = context.getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class).orElseThrow();
        long iat = context.getAttribute(ValidationKeys.IAT, Long.class).orElseThrow();
        boolean naturalPerson = identity.type().isNaturalPerson();

        String text = naturalPerson ? "Assinatura digital validada com sucesso" : "Selo eletrônico validado com sucesso";
        String diagnostics = (naturalPerson ? "assinatura PF" : "selo PJ")
                + "; certificado " + identity.type().label()
                + "; nível " + level.label()
                + "; algoritmo " + Policy020.JWS_ALGORITHM
                + "; política " + Policy020.POLICY_URI
                + "; canonicalização " + Policy020.CANONICALIZATION_URI
                + "; iat " + Instant.ofEpochSecond(iat)
                + "; referência " + Instant.ofEpochSecond(context.getReferenceTimestamp())
                + "; revogação conclusiva via OCSP/CRL (icpbrasil-truststore)";

        OperationOutcome outcome = OperationOutcome.createSignatureError("information", "informational",
                SignatureExceptionCode.VALIDATION_SUCCESS.getCode(), text, diagnostics);
        return StepResult.success(getName(), context.toBuilder().operationOutcome(outcome).build());
    }
}
