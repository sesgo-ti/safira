package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class JwsExtractionStepTest {

    private JwsExtractionStep step;

    @BeforeEach
    void setUp() {
        step = new JwsExtractionStep();
    }

    @Test
    void shouldFailWhenOuterBase64Invalid() {
        var context = contextWith("!!!not-base64!!!");

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldFailWhenJsonMalformed() {
        var context = contextWith(encode("{not json"));

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenPayloadMissing() {
        String jws = "{\"signatures\":[{\"protected\":\"" + encodeUrl("{\"alg\":\"RS256\"}")
                + "\",\"signature\":\"" + encodeUrl("sig") + "\"}]}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenSignaturesMissing() {
        String jws = "{\"payload\":\"" + encodeUrl("payload") + "\"}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenSignaturesEmpty() {
        String jws = "{\"payload\":\"" + encodeUrl("payload") + "\",\"signatures\":[]}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenProtectedMissing() {
        String jws = "{\"payload\":\"" + encodeUrl("payload")
                + "\",\"signatures\":[{\"signature\":\"" + encodeUrl("sig") + "\"}]}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenSignatureValueMissing() {
        String jws = "{\"payload\":\"" + encodeUrl("payload")
                + "\",\"signatures\":[{\"protected\":\"" + encodeUrl("{\"alg\":\"RS256\"}") + "\"}]}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldFailWhenProtectedHeaderBase64Invalid() {
        String jws = "{\"payload\":\"" + encodeUrl("payload")
                + "\",\"signatures\":[{\"protected\":\"!!!\",\"signature\":\"" + encodeUrl("sig") + "\"}]}";
        var result = step.execute(contextWith(encode(jws)));

        assertFailure(result, SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldExtractMinimalJws() {
        String protectedRaw = encodeUrl("{\"alg\":\"RS256\"}");
        String payloadRaw = encodeUrl("payload");
        String sigRaw = encodeUrl("sig");
        String jws = "{\"payload\":\"" + payloadRaw + "\",\"signatures\":[{\"protected\":\""
                + protectedRaw + "\",\"signature\":\"" + sigRaw + "\"}]}";

        var result = step.execute(contextWith(encode(jws)));

        var ctx = assertSuccess(result);
        assertEquals(payloadRaw, ctx.getPayloadBase64Url());
        assertEquals(protectedRaw, ctx.getRawProtectedHeaderBase64Url());
        assertEquals("RS256", ctx.getProtectedHeader().get("alg"));
        assertNull(ctx.getUnprotectedHeader());
        assertArrayEquals(Base64.getUrlDecoder().decode(sigRaw), ctx.getSignatureBytes());
        assertNotNull(ctx.getRawJwsJson());
    }

    @Test
    void shouldExtractJwsWithUnprotectedHeader() {
        String protectedRaw = encodeUrl("{\"alg\":\"RS256\"}");
        String payloadRaw = encodeUrl("payload");
        String sigRaw = encodeUrl("sig");
        String jws = "{\"payload\":\"" + payloadRaw + "\",\"signatures\":[{\"protected\":\""
                + protectedRaw + "\",\"header\":{\"sigTst\":\"xyz\"},\"signature\":\"" + sigRaw + "\"}]}";

        var result = step.execute(contextWith(encode(jws)));

        var ctx = assertSuccess(result);
        assertNotNull(ctx.getUnprotectedHeader());
        assertEquals("xyz", ctx.getUnprotectedHeader().get("sigTst"));
    }

    // ===== Helpers =====

    private static ValidationContext contextWith(String signedDataBase64) {
        return ValidationContext.builder().signedDataBase64(signedDataBase64).build();
    }

    private static String encode(String raw) {
        return Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    private static String encodeUrl(String raw) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
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
