package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps.OcspUnknownHandling;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps.RevocationPolicy;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TimestampPolicyValidationStepTest {

    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.0.0";

    private TimestampPolicyValidationStep step;

    @BeforeEach
    void setUp() {
        step = new TimestampPolicyValidationStep();
    }

    @Test
    void shouldFailWhenIatBeforeNotBefore() throws Exception {
        long ref = 1_800_000_000L;
        long iat = 1_700_000_000L;
        // notBefore after iat
        X509Certificate leaf = leafCert(date(iat + 1000), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD);
    }

    @Test
    void shouldFailWhenIatAfterNotAfter() throws Exception {
        long ref = 1_800_000_000L;
        long iat = 1_700_000_000L;
        X509Certificate leaf = leafCert(date(iat - 86_400), date(iat - 1));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD);
    }

    @Test
    void shouldFailWhenIatAfterReferenceTimestamp() throws Exception {
        long ref = 1_700_000_000L;
        long iat = ref + 1000;
        X509Certificate leaf = leafCert(date(iat - 86_400), date(iat + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldAddClockSkewWarningWhenIatDiffExceeds300s() throws Exception {
        long ref = 1_800_000_000L;
        long iat = ref - 600;
        X509Certificate leaf = leafCert(date(iat - 86_400), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        ValidationContext ok = assertSuccess(result);
        assertTrue(ok.getWarnings().stream().anyMatch(i ->
                SignatureExceptionCode.TEMPORAL_CLOCK_SKEW_DETECTED.getCode()
                        .equals(i.details().coding().get(0).code())));
    }

    @Test
    void shouldReturnSuccessForValidIat() throws Exception {
        long ref = 1_800_000_000L;
        long iat = ref - 100;
        X509Certificate leaf = leafCert(date(iat - 86_400), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        ValidationContext ok = assertSuccess(result);
        assertTrue(ok.getWarnings().isEmpty());
    }

    @Test
    void shouldFailWhenTsaTokenBase64Invalid() throws Exception {
        long ref = 1_800_000_000L;
        X509Certificate leaf = leafCert(date(ref - 86_400), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.TSA, null, ref, leaf, POLICY_URI, "!!!not-base64!!!");

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.TSA_INVALID_TOKEN);
    }

    @Test
    void shouldReturnSuccessAndWarnWhenTsaStubUsed() throws Exception {
        long ref = 1_800_000_000L;
        X509Certificate leaf = leafCert(date(ref - 86_400), date(ref + 86_400 * 365));
        String tsaToken = Base64.getEncoder().encodeToString("dummy".getBytes(StandardCharsets.UTF_8));
        ValidationContext ctx = baseContext(TimestampStrategy.TSA, null, ref, leaf, POLICY_URI, tsaToken);

        StepResult<ValidationContext> result = step.execute(ctx);

        ValidationContext ok = assertSuccess(result);
        assertEquals(ref, ok.getResolvedSignatureTimestamp());
        assertTrue(ok.getWarnings().stream().anyMatch(i ->
                "TSA".equals(i.details().coding().get(0).code())));
    }

    @Test
    void shouldFailWhenSigPIdMismatchesContextPolicy() throws Exception {
        long ref = 1_800_000_000L;
        long iat = ref - 100;
        X509Certificate leaf = leafCert(date(iat - 86_400), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf,
                "https://other-policy|2.0.0", null);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertFailure(result, SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldAddSignatureTooOldWarningWhenAgeExceedsThreshold() throws Exception {
        long ref = 1_800_000_000L;
        long iat = ref - 86_400L * 400; // 400 days old, exceeds default 365
        X509Certificate leaf = leafCert(date(iat - 86_400), date(ref + 86_400 * 365));
        ValidationContext ctx = baseContext(TimestampStrategy.IAT, iat, ref, leaf, POLICY_URI, null);

        StepResult<ValidationContext> result = step.execute(ctx);

        ValidationContext ok = assertSuccess(result);
        assertTrue(ok.getWarnings().stream().anyMatch(i ->
                SignatureExceptionCode.TEMPORAL_SIGNATURE_TOO_OLD.getCode()
                        .equals(i.details().coding().get(0).code())));
    }

    // ===== Helpers =====

    private static Date date(long epochSeconds) {
        return new Date(epochSeconds * 1000L);
    }

    private static X509Certificate leafCert(Date notBefore, Date notAfter) throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        X509Certificate caCert = TestCertificates.buildCaCert(caKp, "Test CA",
                date(1_600_000_000L), date(2_000_000_000L));
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        return TestCertificates.buildLeafCert(leafKp, caKp, caCert, "Signer",
                notBefore, notAfter, TestCertificates.ICP_BRASIL_POLICY_OID);
    }

    private static ValidationContext baseContext(TimestampStrategy strategy, Long iat, long ref,
                                                 X509Certificate leaf, String contextPolicyUri,
                                                 String sigTstBase64) {
        Map<String, Object> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put("alg", "RS256");
        protectedHeader.put("sigPId", new LinkedHashMap<>(Map.of("id", POLICY_URI)));
        if (iat != null) {
            protectedHeader.put("iat", iat);
        }

        Map<String, Object> unprotected = null;
        if (sigTstBase64 != null) {
            unprotected = new LinkedHashMap<>();
            unprotected.put("sigTst", sigTstBase64);
        }

        SafiraOperationalConfigProperties opConfig = new SafiraOperationalConfigProperties(
                null, null, null, null,
                new ValidationPolicyProps(30, 365,
                        RevocationPolicy.STRICT, OcspUnknownHandling.TREAT_AS_REVOKED));

        return ValidationContext.builder()
                .referenceTimestamp(ref)
                .policyIdentifierUri(contextPolicyUri)
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotected)
                .timestampStrategy(strategy)
                .resolvedSignatureTimestamp(strategy == TimestampStrategy.IAT ? iat : null)
                .certificateChain(List.of(leaf))
                .operationalConfig(opConfig)
                .warnings(new ArrayList<>())
                .build();
    }

    private static void assertFailure(StepResult<ValidationContext> result, SignatureExceptionCode expected) {
        StepResult.Failure<ValidationContext> failure = assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expected, failure.code());
    }

    private static ValidationContext assertSuccess(StepResult<ValidationContext> result) {
        StepResult.Success<ValidationContext> success = assertInstanceOf(StepResult.Success.class, result);
        return success.context();
    }
}
