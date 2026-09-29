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
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;

import java.util.List;
import java.util.Optional;

/**
 * Passo {@code timestamp-validation}: seção 5 do caso de uso de validação, somente JAdES-B-T —
 * política do carimbo aceita, message imprint, assinatura CMS/ESSCertID, EKU crítico exclusivo,
 * accuracy, intervalo {@code I} contido em {@code [iat − 300 s, iat + 300 s]}, nas validades das
 * cadeias e anterior ao timestamp de referência, e cadeia TSA terminada em âncora do trust store
 * TSA da política (independente do acervo ICP-Brasil). Revogação da cadeia TSA: {@code dss-validation}.
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
        } catch (IllegalArgumentException e) {
            violation = Optional.of(new PolicyViolation(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, e.getMessage()));
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
                        context.getCertificateChain().orElse(List.of()), context.getReferenceTimestamp())
                .or(() -> TsaChainVerification.chainToAnchor(inspection,
                                TsaTrustStores.load(tsaPolicy.get().trustStore().reference()))
                        .isPresent()
                        ? Optional.empty()
                        : Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED,
                        "A cadeia da TSA não termina em âncora do trust store da política " + tsaPolicy.get().oid() + ".")));
    }
}
