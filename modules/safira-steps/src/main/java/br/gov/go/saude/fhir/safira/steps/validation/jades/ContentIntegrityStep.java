/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest;
import br.gov.go.saude.fhir.safira.steps.content.SignedContentRules;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;

import java.security.MessageDigest;
import java.util.Optional;

/**
 * Passo {@code content-integrity}: seção 3 do caso de uso de validação — regras do conteúdo
 * assinado sobre Bundle/Provenance e recomputação lossless do artefato enquadrado, comparada em
 * tempo constante com os 32 bytes do payload attached.
 */
@StepId("content-integrity")
public class ContentIntegrityStep implements ValidationStep {

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        var limits = context.getOperationalConfig() == null ? null : context.getOperationalConfig().security();
        Optional<PolicyViolation> violation = SignedContentRules.check(context.getBundleJson(), context.getProvenanceJson(), limits);
        if (violation.isPresent()) {
            return StepResult.failure(getName(), violation.get().code(), violation.get().diagnostics(), context);
        }
        byte[] recomputed;
        try {
            recomputed = FramedContentDigest.sha256(
                    SignedContentRules.orderedParts(context.getBundleJson(), context.getProvenanceJson()));
        } catch (RuntimeException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                    "Falha na canonicalização lossless do conteúdo: " + e.getMessage(), context);
        }
        byte[] payload = context.getAttribute(ValidationKeys.PAYLOAD, byte[].class).orElse(new byte[0]);
        if (!MessageDigest.isEqual(recomputed, payload)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED,
                    "O SHA-256 do artefato enquadrado recomputado difere do payload assinado.", context);
        }
        return StepResult.success(getName(), context);
    }
}
