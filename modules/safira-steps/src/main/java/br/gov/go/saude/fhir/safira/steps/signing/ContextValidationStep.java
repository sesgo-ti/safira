/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.policy.OperationalChecks;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyChecks;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.ConfigViolation;

import java.net.URI;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code context-validation}: etapa 1 do caso de uso de criação da política 0.2.0
 * (1.1 política, 1.2/1.10 timestamp de referência, 1.3 resultado pretendido, 1.11
 * configurações operacionais e da política). Executa antes de qualquer processamento
 * criptográfico.
 */
@StepId("context-validation")
public class ContextValidationStep implements SigningStep {

    private final SafiraPolicyProperties policy;
    private final Clock clock;

    public ContextValidationStep(SafiraPolicyProperties policy, Clock clock) {
        this.policy = policy;
        this.clock = clock;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        Optional<PolicyViolation> violation = PolicyChecks.policyUri(context.getPolicyIdentifierUri())
                .or(() -> PolicyChecks.referenceTimestamp(context.getReferenceTimestamp(), clock.instant().getEpochSecond()))
                .or(() -> checkStrategy(context))
                .or(() -> checkMinimumIssueDate(context.getReferenceTimestamp()))
                .or(() -> checkPolicyConfiguration(context.getStrategy() == TimestampStrategy.TSA))
                .or(() -> OperationalChecks.check(context.getOperationalConfig()))
                .or(() -> checkCryptoMaterial(context.getCryptoMaterial()));
        return violation
                .map(v -> StepResult.failure(getName(), v.code(), v.diagnostics(), context))
                .orElseGet(() -> StepResult.success(getName(), context));
    }

    private Optional<PolicyViolation> checkStrategy(SigningContext context) {
        if (context.getStrategy() == null) {
            return fail(SignatureExceptionCode.CONFIG_INVALID_STRATEGY, "Resultado pretendido deve ser 'iat' ou 'tsa'.");
        }
        if (context.getStrategy() != TimestampStrategy.TSA) {
            return Optional.empty();
        }
        SafiraOperationalConfigProperties config = context.getOperationalConfig();
        String tsaUrl = config == null || config.verification() == null ? null : config.verification().tsaUrl();
        if (tsaUrl == null || tsaUrl.isBlank()) {
            return fail(SignatureExceptionCode.CONFIG_MISSING_PARAMETER,
                    "Resultado 'tsa' exige safira.operational.verification.tsa-url.");
        }
        try {
            URI uri = new URI(tsaUrl);
            if (!"https".equals(uri.getScheme()) || uri.getHost() == null) {
                return fail(SignatureExceptionCode.CONFIG_TSA_URL_INVALID, "A URL da TSA deve ser HTTPS válida.");
            }
        } catch (Exception e) {
            return fail(SignatureExceptionCode.CONFIG_TSA_URL_INVALID, "A URL da TSA é inválida (RFC 3986).");
        }
        return Optional.empty();
    }

    private Optional<PolicyViolation> checkMinimumIssueDate(Long referenceTimestamp) {
        if (referenceTimestamp < policy.minCertIssueDate()) {
            return fail(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP,
                    "Timestamp de referência anterior a temporalPolicy.minCertIssueDate.");
        }
        return Optional.empty();
    }

    private Optional<PolicyViolation> checkPolicyConfiguration(boolean tsaRequired) {
        List<ConfigViolation> violations = policy.violations(tsaRequired);
        if (violations.isEmpty()) {
            return Optional.empty();
        }
        ConfigViolation first = violations.getFirst();
        return fail(first.code(), first.diagnostics());
    }

    private Optional<PolicyViolation> checkCryptoMaterial(CryptoMaterial material) {
        if (material == null) {
            return fail(SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "Material criptográfico do signatário ausente.");
        }
        if (material instanceof CryptoMaterial.Pkcs12Material p12) {
            if (p12.password() == null || p12.password().isEmpty()) {
                return fail(SignatureExceptionCode.CONFIG_MISSING_PARAMETER, "A senha do PKCS#12 não foi fornecida.");
            }
            if (p12.alias() != null && (p12.alias().isEmpty() || p12.alias().length() > 64)) {
                return fail(SignatureExceptionCode.MIDDLEWARE_TOKEN_LABEL_INVALID,
                        "O alias do PKCS#12 deve ter entre 1 e 64 caracteres.");
            }
            try {
                Base64.getDecoder().decode(p12.contentBase64() == null ? "" : p12.contentBase64());
            } catch (IllegalArgumentException e) {
                return fail(SignatureExceptionCode.FORMAT_BASE64_INVALID, "O conteúdo PKCS#12 não é Base64 válido.");
            }
        }
        return Optional.empty();
    }

    private static Optional<PolicyViolation> fail(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
