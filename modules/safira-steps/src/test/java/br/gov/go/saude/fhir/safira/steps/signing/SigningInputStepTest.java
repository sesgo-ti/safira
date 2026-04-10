package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class SigningInputStepTest {

    private SigningInputStep step;

    @BeforeEach
    void setUp() {
        step = new SigningInputStep();
    }

    @Test
    void shouldConcatenateHeaderAndPayloadWithDotSeparator() {
        String header = "eyJhbGciOiJSUzI1NiJ9";
        String digest = "dGVzdC1kaWdlc3QtdmFsdWUtZm9yLXRlc3Rpbmc0NTY";
        var context = contextWith(header, digest);

        var result = step.execute(context);

        assertSuccess(result);
        assertEquals("eyJhbGciOiJSUzI1NiJ9.dGVzdC1kaWdlc3QtdmFsdWUtZm9yLXRlc3Rpbmc0NTY", signingInput(result));
    }

    @Test
    void shouldProduceUtf8BytesOfSigningInput() {
        String header = "eyJhbGciOiJSUzI1NiJ9";
        String digest = "abc123";
        var context = contextWith(header, digest);

        var result = step.execute(context);

        assertSuccess(result);
        String expected = header + "." + digest;
        assertArrayEquals(expected.getBytes(StandardCharsets.UTF_8), signingInputBytes(result));
    }

    @Test
    void shouldNotReEncodePayload() {
        String header = "eyJhbGciOiJSUzI1NiJ9";
        String digest = "already-base64url-43chars-no-padding-here";
        var context = contextWith(header, digest);

        var result = step.execute(context);

        assertSuccess(result);
        assertTrue(signingInput(result).endsWith("." + digest));
    }

    @Test
    void shouldThrowWhenProtectedHeaderMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, "some-digest")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowWhenContentDigestMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, "some-header")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(String protectedHeader, String contentDigest) {
        return SigningContext.builder()
                .attribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, protectedHeader)
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, contentDigest)
                .build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private String signingInput(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(SigningInputStep.SIGNING_INPUT_KEY, String.class).orElseThrow();
    }

    private byte[] signingInputBytes(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(SigningInputStep.SIGNING_INPUT_BYTES_KEY, byte[].class).orElseThrow();
    }
}
