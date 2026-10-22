/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.content.SignedContentRules;

/**
 * Passo {@code payload-validation}: etapas 1.4 a 1.9 do caso de uso de criação — estrutura do
 * Bundle e do Provenance, correspondência {@code Provenance.target} × {@code Bundle.entry.fullUrl},
 * limites de segurança e formas admitidas de {@code Reference} (C5).
 */
@StepId("payload-validation")
public class PayloadValidationStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        if (context.getBundleJson() == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED,
                    "O Bundle não foi fornecido.", context);
        }
        if (context.getProvenanceJson() == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_PROVENANCE_INVALID,
                    "O Provenance não foi fornecido.", context);
        }
        var limits = context.getOperationalConfig() == null ? null : context.getOperationalConfig().security();
        return SignedContentRules.check(context.getBundleJson(), context.getProvenanceJson(), limits)
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }
}
