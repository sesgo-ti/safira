/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;

import java.util.Arrays;
import java.util.Optional;

/**
 * Passo {@code tsa-token-verification}: etapa 12.3 do caso de uso de criação — valida o
 * {@code TimeStampToken} incorporado pelo {@code jades-extension} antes de devolver a assinatura:
 * política, message imprint, assinatura CMS/ESSCertID, EKU, accuracy, intervalo {@code I} frente
 * a {@code iat ± 300 s} e às validades, e a cadeia da TSA ancorada exclusivamente no trust store
 * TSA da política (com revogação). No resultado {@code iat} não há carimbo e o passo é neutro.
 */
@StepId("tsa-token-verification")
public class TsaTokenVerificationStep implements SigningStep {

    private final PkixCertificateValidator validator;
    private final SafiraPolicyProperties policy;

    public TsaTokenVerificationStep(PkixCertificateValidator validator, SafiraPolicyProperties policy) {
        this.validator = validator;
        this.policy = policy;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        if (context.getStrategy() != TimestampStrategy.TSA) {
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

    private Optional<PolicyViolation> verify(SigningContext context) {
        String jws = context.getAttribute(SigningKeys.JWS_FINAL, String.class)
                .orElseThrow(() -> new TimestampTokenException(SignatureExceptionCode.TSA_INVALID_TOKEN,
                        "JWS estendido ausente do contexto."));
        Inspection inspection = TimestampTokenInspector.inspect(TimestampTokenInspector.tokenFromJws(jws));
        Optional<TsaPolicy> tsaPolicy = TsaChainVerification.selectPolicy(policy, inspection);
        if (tsaPolicy.isEmpty()) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                    "Política do carimbo " + inspection.policyOid() + " não consta de safira.policy.tsa-policies."));
        }
        return TimestampTokenInspector.verify(inspection, TsaChainVerification.signatureText(jws),
                        context.getReferenceTimestamp(), tsaPolicy.get(),
                        Arrays.asList(context.getCertificateChain().orElseThrow()), Long.MAX_VALUE)
                .or(() -> TsaChainVerification.verify(validator, inspection, tsaPolicy.get()));
    }
}
