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
import br.gov.go.saude.fhir.safira.steps.policy.OperationalChecks;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyChecks;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.ConfigViolation;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;

import java.time.Clock;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code validation-context}: seção 0 do caso de uso de validação da política 0.2.0 —
 * entradas obrigatórias (Signature, Bundle, Provenance), política solicitada, timestamp de
 * referência, configurações e disponibilidade do acervo ICP-Brasil.
 */
@StepId("validation-context")
public class ValidationRequestContextStep implements ValidationStep {

    private final SafiraPolicyProperties policy;
    private final TrustMaterialSource trustMaterialSource;
    private final Clock clock;

    public ValidationRequestContextStep(SafiraPolicyProperties policy, TrustMaterialSource trustMaterialSource,
                                        Clock clock) {
        this.policy = policy;
        this.trustMaterialSource = trustMaterialSource;
        this.clock = clock;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        Optional<PolicyViolation> violation = checkInputs(context)
                .or(() -> PolicyChecks.policyUri(context.getPolicyIdentifierUri()))
                .or(() -> PolicyChecks.referenceTimestamp(context.getReferenceTimestamp(), clock.instant().getEpochSecond()))
                .or(this::checkPolicyConfiguration)
                .or(() -> OperationalChecks.check(context.getOperationalConfig()))
                .or(this::checkTrustStore);
        return violation
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }

    private static Optional<PolicyViolation> checkInputs(ValidationContext context) {
        if (context.getSignatureJson() == null) {
            return fail(SignatureExceptionCode.FORMAT_SIGNATURE_MISSING, "A instância Signature (entrada 1) não foi fornecida.");
        }
        if (context.getBundleJson() == null) {
            return fail(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED, "O Bundle (entrada 2) não foi fornecido.");
        }
        if (context.getProvenanceJson() == null) {
            return fail(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID, "O Provenance final (entrada 3) não foi fornecido.");
        }
        return Optional.empty();
    }

    private Optional<PolicyViolation> checkPolicyConfiguration() {
        List<ConfigViolation> violations = policy.violations(false);
        return violations.isEmpty()
                ? Optional.empty()
                : fail(violations.getFirst().code(), violations.getFirst().diagnostics());
    }

    private Optional<PolicyViolation> checkTrustStore() {
        boolean available = trustMaterialSource.current().filter(t -> t.hasAnchors()).isPresent();
        return available ? Optional.empty() : fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                "Acervo ICP-Brasil indisponível ou expirado: nenhuma âncora de confiança carregada.");
    }

    private static Optional<PolicyViolation> fail(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
