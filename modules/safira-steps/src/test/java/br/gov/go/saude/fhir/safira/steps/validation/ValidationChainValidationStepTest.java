package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.TrustStoreProps;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.ValidationPolicyProps;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationChainValidationStepTest {

    private static final long MIN_DATE = 1_751_328_000L; // 2025-07-01
    private static final long LEAF_START = 1_754_006_400L; // 2025-08-01
    private static final long REF_TS = 1_756_684_800L; // 2025-09-01
    private static final long CERT_END = 1_893_456_000L; // 2030-01-01

    private ValidationChainValidationStep step;

    @BeforeEach
    void setUp() {
        step = new ValidationChainValidationStep();
    }

    @Test
    void shouldFailWhenChainLessThanTwo() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root", date(LEAF_START), date(CERT_END));
        ValidationContext ctx = contextBuilder(List.of(ca),
                List.of(TestCertificates.sha256Hex(ca))).build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenRootHashNotInTrustStore() throws Exception {
        List<X509Certificate> chain = validChain();
        ValidationContext ctx = contextBuilder(chain, List.of("0".repeat(64))).build();

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.CERT_NOT_ICP_BRASIL, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenLeafLacksIcpBrasilPolicy() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(LEAF_START), date(CERT_END), null);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, ca), trust).build());

        assertEquals(SignatureExceptionCode.CERT_NOT_ICP_BRASIL, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenLeafNotBeforeBelowMinCertDate() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        long tooOld = MIN_DATE - 86_400L;
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(tooOld), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(tooOld), date(CERT_END), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, ca), trust).build());

        assertEquals(SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenAnyCertExpired() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        long leafEnd = REF_TS - 86_400L;
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(LEAF_START), date(leafEnd), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, ca), trust).build());

        assertEquals(SignatureExceptionCode.CERT_EXPIRED, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenAnyCertNotYetValid() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        long future = REF_TS + 86_400L;
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(future), date(CERT_END), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, ca), trust).build());

        assertEquals(SignatureExceptionCode.CERT_NOT_YET_VALID, assertFailure(result).code());
    }

    @Test
    void shouldFailWhenHierarchySignatureBroken() throws Exception {
        // leaf signed by a DIFFERENT CA key than the CA cert in chain position 1
        KeyPair realCaKp = TestCertificates.rsaKeyPair(2048);
        KeyPair attackerCaKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        X509Certificate realCa = TestCertificates.buildCaCert(realCaKp, "Root",
                date(LEAF_START), date(CERT_END));
        // The leaf is built using attackerCaKp (signer) but we set issuer name to realCa's subject.
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, attackerCaKp, realCa, "Leaf",
                date(LEAF_START), date(CERT_END), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(realCa));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, realCa), trust).build());

        assertEquals(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                assertFailure(result).code());
    }

    @Test
    void shouldFailWhenRsaKeyTooSmall() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(1024);
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(LEAF_START), date(CERT_END), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(List.of(leaf, ca), trust).build());

        assertEquals(SignatureExceptionCode.CERT_WEAK_KEY, assertFailure(result).code());
    }

    @Test
    void shouldAddNearExpiryWarningWhenWithinThreshold() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        // leaf expires in 10 days from REF_TS (< 30-day threshold)
        long leafEnd = REF_TS + 10L * 86_400L;
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(LEAF_START), date(leafEnd), TestCertificates.ICP_BRASIL_POLICY_OID);
        List<String> trust = List.of(TestCertificates.sha256Hex(ca));

        ValidationContext ctx = contextBuilder(List.of(leaf, ca), trust).build();
        StepResult<ValidationContext> result = step.execute(ctx);

        StepResult.Success<ValidationContext> success =
                assertInstanceOf(StepResult.Success.class, result);
        List<OperationOutcome.Issue> warnings = success.context().getWarnings();
        assertFalse(warnings.isEmpty());
        assertTrue(warnings.stream().anyMatch(issue ->
                issue.details() != null
                        && issue.details().coding() != null
                        && issue.details().coding().stream().anyMatch(c ->
                                SignatureExceptionCode.CERT_NEAR_EXPIRY.getCode().equals(c.code()))));
    }

    @Test
    void shouldReturnSuccessForValidChain() throws Exception {
        List<X509Certificate> chain = validChain();
        List<String> trust = List.of(TestCertificates.sha256Hex(chain.get(1)));

        StepResult<ValidationContext> result = step.execute(
                contextBuilder(chain, trust).build());

        assertInstanceOf(StepResult.Success.class, result);
    }

    // ===== Helpers =====

    private static List<X509Certificate> validChain() throws Exception {
        KeyPair caKp = TestCertificates.rsaKeyPair(2048);
        KeyPair leafKp = TestCertificates.rsaKeyPair(2048);
        X509Certificate ca = TestCertificates.buildCaCert(caKp, "Root",
                date(LEAF_START), date(CERT_END));
        X509Certificate leaf = TestCertificates.buildLeafCert(leafKp, caKp, ca, "Leaf",
                date(LEAF_START), date(CERT_END), TestCertificates.ICP_BRASIL_POLICY_OID);
        return List.of(leaf, ca);
    }

    private static Date date(long epochSec) {
        return new Date(epochSec * 1000L);
    }

    private static ValidationContext.ValidationContextBuilder contextBuilder(
            List<X509Certificate> chain, List<String> trustedHashes) {
        TrustStoreProps trustStore = new TrustStoreProps(
                null, null, 30, 3, null, null, null, null,
                1440, 2880, 10080, MIN_DATE, trustedHashes);
        ValidationPolicyProps validationPolicy = new ValidationPolicyProps(
                30, 365,
                ValidationPolicyProps.RevocationPolicy.STRICT,
                ValidationPolicyProps.OcspUnknownHandling.TREAT_AS_REVOKED);
        SafiraOperationalConfigProperties opConfig = new SafiraOperationalConfigProperties(
                null, trustStore, null, null, validationPolicy);
        return ValidationContext.builder()
                .certificateChain(chain)
                .referenceTimestamp(REF_TS)
                .operationalConfig(opConfig)
                .warnings(new ArrayList<>());
    }

    private static StepResult.Failure<ValidationContext> assertFailure(StepResult<ValidationContext> r) {
        return assertInstanceOf(StepResult.Failure.class, r);
    }
}
