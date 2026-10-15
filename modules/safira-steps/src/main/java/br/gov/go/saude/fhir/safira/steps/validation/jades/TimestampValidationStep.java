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
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;

import java.util.List;
import java.util.Optional;

/**
 * Passo {@code timestamp-validation}: regras da política 0.2.0 para o carimbo de JAdES-B-T que o
 * EU DSS não verifica — política do carimbo aceita, imprint SHA-256 sobre o texto de
 * {@code signature}, EKU crítico exclusivo, accuracy e intervalo {@code I} contido em
 * {@code [iat − 300 s, iat + 300 s]}, nas validades das cadeias e anterior ao timestamp de
 * referência. Cadeia, revogação e âncora TSA da política: {@code dss-validation}.
 */
@StepId("timestamp-validation")
public class TimestampValidationStep implements ValidationStep {

    private final SafiraPolicyProperties policy;

    public TimestampValidationStep(SafiraPolicyProperties policy) {
        this.policy = policy;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        if (context.getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class).orElse(JadesLevel.B_B) != JadesLevel.B_T) {
            return StepResult.success(getName(), context);
        }
        Optional<PolicyViolation> violation;
        try {
            violation = verify(context);
        } catch (TimestampTokenException e) {
            violation = Optional.of(new PolicyViolation(e.getCode(), e.getMessage()));
        }
        return violation
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }

    private Optional<PolicyViolation> verify(ValidationContext context) {
        String jws = context.getAttribute(ValidationKeys.JWS_JSON, String.class).orElseThrow();
        Inspection inspection = TimestampTokenInspector.inspect(TimestampTokenInspector.tokenFromJws(jws));
        Optional<TsaPolicy> tsaPolicy = TsaChainVerification.selectPolicy(policy, inspection);
        if (tsaPolicy.isEmpty()) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                    "Política do carimbo " + inspection.policyOid() + " não consta de safira.policy.tsa-policies."));
        }
        long iat = context.getAttribute(ValidationKeys.IAT, Long.class).orElseThrow();
        String signatureText = context.getAttribute(ValidationKeys.SIGNATURE_TEXT, String.class).orElseThrow();
        return TimestampTokenInspector.verify(inspection, signatureText, iat, tsaPolicy.get(),
                context.getCertificateChain().orElse(List.of()), context.getReferenceTimestamp());
    }
}
