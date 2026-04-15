package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.MiddlewareCryptoProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.SecurityLimitsProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.TrustStoreProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps.OcspUnknownHandling;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps.RevocationPolicy;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.VerificationProps;
import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineKey;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class ValidationContextValidationStepTest {

    private static final String SUPPORTED_POLICY =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";
    private static final long VALID_TS = 1_800_000_000L;

    private ValidationContextValidationStep step;

    @BeforeEach
    void setUp() {
        PipelineDefinition def = new PipelineDefinition(
                new PipelineKey(SUPPORTED_POLICY, OperationType.VALIDATION),
                List.of("validation-context-validation"));
        step = new ValidationContextValidationStep(List.of(def));
    }

    @Test
    void shouldFailWhenMinCertDateNotPositive() {
        var cfg = configWithTrustStore(trustStore(0L));

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_CERT_MIN_DATE_INVALID);
    }

    @Test
    void shouldFailWhenMinCertDateBelowLowerBound() {
        var cfg = configWithTrustStore(trustStore(1_000_000_000L));

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_CERT_MIN_DATE_OUT_OF_RANGE);
    }

    @Test
    void shouldFailWhenOcspTimeoutOutOfRange() {
        var verification = new VerificationProps(3600, 3600, 3, 20, 20, 3, 2, null, null, null);
        var cfg = configWithVerification(verification);

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_TIMEOUT_OUT_OF_RANGE);
    }

    @Test
    void shouldFailWhenTtlOutOfRange() {
        var verification = new VerificationProps(100, 3600, 20, 20, 20, 3, 2, null, null, null);
        var cfg = configWithVerification(verification);

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_TTL_OUT_OF_RANGE);
    }

    @Test
    void shouldFailWhenNearExpiryThresholdOutOfRange() {
        var policy = new ValidationPolicyProps(0, 365, RevocationPolicy.STRICT, OcspUnknownHandling.TREAT_AS_REVOKED);
        var cfg = configWithValidationPolicy(policy);

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldFailWhenSignatureAgeThresholdOutOfRange() {
        var policy = new ValidationPolicyProps(30, 5000, RevocationPolicy.STRICT, OcspUnknownHandling.TREAT_AS_REVOKED);
        var cfg = configWithValidationPolicy(policy);

        var result = step.execute(buildContext(cfg, VALID_TS, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldFailWhenReferenceTimestampOutOfRange() {
        var result = step.execute(buildContext(validConfig(), 100L, SUPPORTED_POLICY));

        assertFailure(result, SignatureExceptionCode.CONFIG_TIMESTAMP_OUT_OF_RANGE);
    }

    @Test
    void shouldFailWhenPolicyUriNotSupported() {
        var result = step.execute(buildContext(validConfig(), VALID_TS, "https://unknown.policy|9.9.9"));

        assertFailure(result, SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED);
    }

    @Test
    void shouldReturnSuccessWhenAllConfigValid() {
        var result = step.execute(buildContext(validConfig(), VALID_TS, SUPPORTED_POLICY));

        assertInstanceOf(StepResult.Success.class, result);
    }

    // ===== Helpers =====

    private static SafiraOperationalConfigProperties validConfig() {
        return new SafiraOperationalConfigProperties(
                defaultVerification(),
                defaultTrustStore(),
                defaultSecurity(),
                new MiddlewareCryptoProps(null, null, null, null),
                defaultValidationPolicy());
    }

    private static SafiraOperationalConfigProperties configWithTrustStore(TrustStoreProps trustStore) {
        return new SafiraOperationalConfigProperties(
                defaultVerification(),
                trustStore,
                defaultSecurity(),
                new MiddlewareCryptoProps(null, null, null, null),
                defaultValidationPolicy());
    }

    private static SafiraOperationalConfigProperties configWithVerification(VerificationProps verification) {
        return new SafiraOperationalConfigProperties(
                verification,
                defaultTrustStore(),
                defaultSecurity(),
                new MiddlewareCryptoProps(null, null, null, null),
                defaultValidationPolicy());
    }

    private static SafiraOperationalConfigProperties configWithValidationPolicy(ValidationPolicyProps policy) {
        return new SafiraOperationalConfigProperties(
                defaultVerification(),
                defaultTrustStore(),
                defaultSecurity(),
                new MiddlewareCryptoProps(null, null, null, null),
                policy);
    }

    private static VerificationProps defaultVerification() {
        return new VerificationProps(3600, 3600, 20, 20, 20, 3, 2, null, null, null);
    }

    private static TrustStoreProps defaultTrustStore() {
        return trustStore(1_751_328_000L);
    }

    private static TrustStoreProps trustStore(Long minCertDate) {
        return new TrustStoreProps(null, null, 30, 3, null, null, null, null,
                1440, 2880, 10080, minCertDate);
    }

    private static SecurityLimitsProps defaultSecurity() {
        return new SecurityLimitsProps(1000, 52428800, 10, 1_751_328_000L, 4_102_444_800L);
    }

    private static ValidationPolicyProps defaultValidationPolicy() {
        return new ValidationPolicyProps(30, 365, RevocationPolicy.STRICT, OcspUnknownHandling.TREAT_AS_REVOKED);
    }

    private static ValidationContext buildContext(SafiraOperationalConfigProperties cfg, long ts, String policy) {
        return ValidationContext.builder()
                .operationalConfig(cfg)
                .referenceTimestamp(ts)
                .policyIdentifierUri(policy)
                .build();
    }

    private static void assertFailure(StepResult<ValidationContext> result, SignatureExceptionCode expected) {
        StepResult.Failure<ValidationContext> failure = assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expected, failure.code());
    }
}
