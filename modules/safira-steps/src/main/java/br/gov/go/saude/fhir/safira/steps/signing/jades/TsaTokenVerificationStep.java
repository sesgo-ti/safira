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
import br.gov.go.saude.fhir.safira.jades.TimestampValidationService;
import br.gov.go.saude.fhir.safira.steps.dss.DssOutcomes;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.fhir.safira.steps.trust.IcpBrasilCertificateVerifiers;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code tsa-token-verification}: etapa 12.3 do caso de uso de criação — valida o
 * {@code TimeStampToken} incorporado pelo {@code jades-extension} antes de devolver a assinatura.
 * As regras da política 0.2.0 (política, imprint SHA-256, EKU, accuracy, intervalo {@code I}
 * frente a {@code iat ± 300 s} e às validades) ficam no {@link TimestampTokenInspector}; assinatura
 * CMS, cadeia e revogação da TSA, pelo EU DSS ({@link TimestampValidationService}), com âncoras
 * exclusivamente do trust store TSA da política. No resultado {@code iat} o passo é neutro.
 */
@StepId("tsa-token-verification")
public class TsaTokenVerificationStep implements SigningStep {

    private final IcpBrasilCertificateVerifiers verifiers;
    private final SafiraPolicyProperties policy;
    private final TimestampValidationService validationService = new TimestampValidationService();

    public TsaTokenVerificationStep(IcpBrasilCertificateVerifiers verifiers, SafiraPolicyProperties policy) {
        this.verifiers = verifiers;
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
        } catch (IllegalArgumentException e) {
            violation = Optional.of(new PolicyViolation(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, e.getMessage()));
        }
        return violation
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }

    private Optional<PolicyViolation> verify(SigningContext context) {
        String jws = context.getAttribute(SigningKeys.JWS_FINAL, String.class)
                .orElseThrow(() -> new TimestampTokenException(SignatureExceptionCode.TSA_INVALID_TOKEN,
                        "JWS estendido ausente do contexto."));
        byte[] token = TimestampTokenInspector.tokenFromJws(jws);
        Inspection inspection = TimestampTokenInspector.inspect(token);
        Optional<TsaPolicy> tsaPolicy = TsaChainVerification.selectPolicy(policy, inspection);
        if (tsaPolicy.isEmpty()) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                    "Política do carimbo " + inspection.policyOid() + " não consta de safira.policy.tsa-policies."));
        }
        String signatureText = TsaChainVerification.signatureText(jws);
        Optional<PolicyViolation> rules = TimestampTokenInspector.verify(inspection, signatureText,
                context.getReferenceTimestamp(), tsaPolicy.get(),
                Arrays.asList(context.getCertificateChain().orElseThrow()), Long.MAX_VALUE);
        if (rules.isPresent()) {
            return rules;
        }
        List<X509Certificate> anchors = TsaTrustStores.load(tsaPolicy.get().trustStore().reference());
        Optional<CommonCertificateVerifier> verifier = verifiers.current(anchors);
        if (verifier.isEmpty()) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                    "Acervo ICP-Brasil indisponível."));
        }
        Reports reports = validationService.validate(token, signatureText.getBytes(StandardCharsets.US_ASCII),
                verifier.get());
        return DssOutcomes.timestamp(reports, reports.getSimpleReport().getFirstTimestampId(), anchors,
                tsaPolicy.get().oid());
    }
}
