package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class JwsHeadersValidationStepTest {

    private static final String SHA512_URI = "http://www.w3.org/2001/04/xmlenc#sha512";
    private static final String DIGEST_A = makeDigest('a');
    private static final String DIGEST_B = makeDigest('b');
    private static final String DIGEST_C = makeDigest('c');

    private JwsHeadersValidationStep step;

    @BeforeEach
    void setUp() {
        step = new JwsHeadersValidationStep();
    }

    @Test
    void shouldFailWhenAlgMissing() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.remove("alg");

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM);
    }

    @Test
    void shouldFailWhenAlgUnsupported() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.put("alg", "HS256");

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM);
    }

    @Test
    void shouldFailWhenX5cMissing() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.remove("x5c");

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    @Test
    void shouldFailWhenX5cEmpty() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.put("x5c", List.of());

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    @Test
    void shouldFailWhenX5cElementNotString() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.put("x5c", List.of(42));

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    @Test
    void shouldFailWhenSigPIdMissing() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.remove("sigPId");

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED);
    }

    @Test
    void shouldFailWhenIatNotANumber() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        protectedHeader.put("iat", "not-a-number");

        var result = step.execute(contextWith(protectedHeader, validUnprotectedHeaderIat()));

        assertFailure(result, SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldFailWhenRRefsMissing() {
        Map<String, Object> protectedHeader = validProtectedHeaderWithIat();
        Map<String, Object> unprotected = new HashMap<>();

        var result = step.execute(contextWith(protectedHeader, unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID);
    }

    @Test
    void shouldFailWhenDigestAlgWrong() {
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        List<Map<String, Object>> ocspRefs = new ArrayList<>();
        ocspRefs.add(Map.of("digestAlg", "sha1", "digestValue", DIGEST_A));
        ((Map<String, Object>) unprotected.get("rRefs")).put("ocspRefs", ocspRefs);

        var result = step.execute(contextWith(validProtectedHeaderWithIat(), unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID);
    }

    @Test
    void shouldFailWhenDigestValueSizeWrong() {
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        List<Map<String, Object>> ocspRefs = new ArrayList<>();
        ocspRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", "tooShort"));
        ((Map<String, Object>) unprotected.get("rRefs")).put("ocspRefs", ocspRefs);

        var result = step.execute(contextWith(validProtectedHeaderWithIat(), unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID);
    }

    @Test
    void shouldFailWhenDuplicateDigestInOcspRefs() {
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        List<Map<String, Object>> ocspRefs = new ArrayList<>();
        ocspRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_A));
        ocspRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_A));
        ((Map<String, Object>) unprotected.get("rRefs")).put("ocspRefs", ocspRefs);

        var result = step.execute(contextWith(validProtectedHeaderWithIat(), unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID);
    }

    @Test
    void shouldFailWhenDigestDuplicatedAcrossOcspAndCrl() {
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        List<Map<String, Object>> ocspRefs = new ArrayList<>();
        ocspRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_A));
        List<Map<String, Object>> crlRefs = new ArrayList<>();
        crlRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_A));
        Map<String, Object> rRefs = (Map<String, Object>) unprotected.get("rRefs");
        rRefs.put("ocspRefs", ocspRefs);
        rRefs.put("crlRefs", crlRefs);

        var result = step.execute(contextWith(validProtectedHeaderWithIat(), unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_LTV_EVIDENCE_INVALID);
    }

    @Test
    void shouldFailWhenBothIatAndSigTstPresent() {
        Map<String, Object> protectedHeader = validProtectedHeaderWithIat();
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        unprotected.put("sigTst", base64("tsa-token"));

        var result = step.execute(contextWith(protectedHeader, unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_TIMESTAMP_STRATEGY_INVALID);
    }

    @Test
    void shouldFailWhenNeitherIatNorSigTstPresent() {
        Map<String, Object> protectedHeader = validProtectedHeader();
        Map<String, Object> unprotected = validUnprotectedHeaderIat();

        var result = step.execute(contextWith(protectedHeader, unprotected));

        assertFailure(result, SignatureExceptionCode.VALIDATION_TIMESTAMP_STRATEGY_INVALID);
    }

    @Test
    void shouldDetectIatStrategy() {
        var result = step.execute(contextWith(validProtectedHeaderWithIat(), validUnprotectedHeaderIat()));

        var ctx = assertSuccess(result);
        assertEquals(TimestampStrategy.IAT, ctx.getTimestampStrategy());
        assertEquals(1_800_000_000L, ctx.getResolvedSignatureTimestamp());
    }

    @Test
    void shouldDetectTsaStrategy() {
        Map<String, Object> unprotected = validUnprotectedHeaderIat();
        unprotected.put("sigTst", base64("tsa-token"));

        var result = step.execute(contextWith(validProtectedHeader(), unprotected));

        var ctx = assertSuccess(result);
        assertEquals(TimestampStrategy.TSA, ctx.getTimestampStrategy());
    }

    // ===== Helpers =====

    private static Map<String, Object> validProtectedHeader() {
        Map<String, Object> header = new LinkedHashMap<>();
        header.put("alg", "RS256");
        header.put("x5c", List.of("cert-base64"));
        header.put("sigPId", new LinkedHashMap<>(Map.of("id", "https://policy|1.0.0")));
        return header;
    }

    private static Map<String, Object> validProtectedHeaderWithIat() {
        Map<String, Object> header = validProtectedHeader();
        header.put("iat", 1_800_000_000L);
        return header;
    }

    private static Map<String, Object> validUnprotectedHeaderIat() {
        Map<String, Object> header = new LinkedHashMap<>();
        Map<String, Object> rRefs = new LinkedHashMap<>();
        List<Map<String, Object>> ocspRefs = new ArrayList<>();
        ocspRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_B));
        List<Map<String, Object>> crlRefs = new ArrayList<>();
        crlRefs.add(Map.of("digestAlg", SHA512_URI, "digestValue", DIGEST_C));
        rRefs.put("ocspRefs", ocspRefs);
        rRefs.put("crlRefs", crlRefs);
        header.put("rRefs", rRefs);
        return header;
    }

    private static ValidationContext contextWith(Map<String, Object> protectedHeader, Map<String, Object> unprotected) {
        return ValidationContext.builder()
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotected)
                .build();
    }

    private static String makeDigest(char filler) {
        byte[] bytes = new byte[64];
        for (int i = 0; i < bytes.length; i++) bytes[i] = (byte) filler;
        return Base64.getEncoder().encodeToString(bytes);
    }

    private static String base64(String raw) {
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
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
