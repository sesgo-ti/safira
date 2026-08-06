/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.TrustStoreProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.VerificationProps;
import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@StepId("validation-context-validation")
public class ValidationContextValidationStep implements ValidationStep {

    private static final long MIN_CERT_DATE_LOWER = 1609459200L; // 2021-01-01T00:00:00Z
    private static final long MIN_CERT_DATE_UPPER = 4102444800L; // 2100-01-01T00:00:00Z
    private static final long REFERENCE_TS_LOWER = 1751328000L;  // 2025-07-01T00:00:00Z
    private static final long REFERENCE_TS_UPPER = 4102444800L;  // 2100-01-01T00:00:00Z

    private final Set<String> supportedPolicies;

    public ValidationContextValidationStep(List<PipelineDefinition> definitions) {
        this.supportedPolicies = definitions == null ? Set.of() : definitions.stream()
                .filter(def -> def.pipelineKey() != null && def.pipelineKey().operation() == OperationType.VALIDATION)
                .map(def -> def.pipelineKey().politicsVersion())
                .collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        StepResult<ValidationContext> fail;

        SafiraOperationalConfigProperties config = context.getOperationalConfig();

        if ((fail = verifyTrustStore(config, context)) != null) return fail;
        if ((fail = verifyMinCertDate(config.trustStore(), context)) != null) return fail;
        if ((fail = verifyTimeouts(config.verification(), context)) != null) return fail;
        if ((fail = verifyTtls(config.verification(), context)) != null) return fail;
        if ((fail = verifyValidationPolicy(config.validationPolicy(), context)) != null) return fail;
        if ((fail = verifyReferenceTimestamp(context.getReferenceTimestamp(), context)) != null) return fail;
        if ((fail = verifyPolicyUri(context.getPolicyIdentifierUri(), context)) != null) return fail;

        return StepResult.success(getName(), context);
    }

    private StepResult<ValidationContext> verifyTrustStore(SafiraOperationalConfigProperties config, ValidationContext context) {
        // TODO(validation): integrar com trust-store resolver real
        if (config == null || config.trustStore() == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                    "Trust store não configurado.", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyMinCertDate(TrustStoreProps trustStore, ValidationContext context) {
        Long minDate = trustStore.minimumCertificateDate();
        if (minDate == null || minDate <= 0) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_CERT_MIN_DATE_INVALID,
                    "Data mínima de certificado inválida.", context);
        }
        if (minDate < MIN_CERT_DATE_LOWER || minDate > MIN_CERT_DATE_UPPER) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_CERT_MIN_DATE_OUT_OF_RANGE,
                    "Data mínima de certificado fora da faixa permitida.", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyTimeouts(VerificationProps verification, ValidationContext context) {
        if (verification == null) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_INVALID_PARAMETER,
                    "Configurações de verificação ausentes.", context);
        }
        if (outOfRange(verification.ocspTimeout(), 5, 120)
                || outOfRange(verification.crlTimeout(), 5, 120)
                || outOfRange(verification.tsaTimeout(), 5, 120)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TIMEOUT_OUT_OF_RANGE,
                    "Timeout de verificação fora da faixa [5,120].", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyTtls(VerificationProps verification, ValidationContext context) {
        if (outOfRange(verification.ocspCacheTtl(), 300, 86400)
                || outOfRange(verification.crlCacheTtl(), 300, 86400)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TTL_OUT_OF_RANGE,
                    "TTL de cache de revogação fora da faixa [300,86400].", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyValidationPolicy(ValidationPolicyProps policy, ValidationContext context) {
        if (policy == null
                || policy.revocationPolicy() == null
                || policy.ocspUnknownHandling() == null
                || outOfRange(policy.nearExpiryThresholdDays(), 1, 180)
                || outOfRange(policy.signatureAgeThresholdDays(), 1, 1825)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_INVALID_PARAMETER,
                    "Parâmetros da política de validação inválidos.", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyReferenceTimestamp(Long refTs, ValidationContext context) {
        if (refTs == null || refTs < REFERENCE_TS_LOWER || refTs > REFERENCE_TS_UPPER) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TIMESTAMP_OUT_OF_RANGE,
                    "Timestamp de referência fora da faixa permitida.", context);
        }
        return null;
    }

    private StepResult<ValidationContext> verifyPolicyUri(String policyUri, ValidationContext context) {
        if (policyUri == null || !supportedPolicies.contains(policyUri)) {
            return StepResult.failure(getName(), SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED,
                    "Versão da política não suportada pelo engine.", context);
        }
        return null;
    }

    private static boolean outOfRange(Integer value, int min, int max) {
        return value == null || value < min || value > max;
    }
}
