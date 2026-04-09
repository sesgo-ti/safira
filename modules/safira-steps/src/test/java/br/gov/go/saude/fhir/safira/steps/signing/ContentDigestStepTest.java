package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ContentDigestStepTest {

    private ContentDigestStep step;

    @BeforeEach
    void setUp() {
        step = new ContentDigestStep();
    }

    @Test
    void shouldProduceBase64UrlEncodedSha256Digest() throws Exception {
        String resource = "{\"resourceType\":\"Patient\"}";
        var context = contextWith(List.of(resource));

        var result = step.execute(context);

        assertSuccess(result);
        String digest = contentDigest(result);
        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(resource.getBytes(StandardCharsets.UTF_8));
        String expectedDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(expected);
        assertEquals(expectedDigest, digest);
    }

    @Test
    void shouldProduceExactly43Characters() {
        var context = contextWith(List.of("{\"a\":1}"));

        var result = step.execute(context);

        assertSuccess(result);
        assertEquals(43, contentDigest(result).length());
    }

    @Test
    void shouldConcatenateResourcesBytesWithoutSeparators() throws Exception {
        String r1 = "{\"a\":1}";
        String r2 = "{\"b\":2}";
        var context = contextWith(List.of(r1, r2));

        var result = step.execute(context);

        assertSuccess(result);
        byte[] concatenated = (r1 + r2).getBytes(StandardCharsets.UTF_8);
        byte[] expected = MessageDigest.getInstance("SHA-256").digest(concatenated);
        String expectedDigest = Base64.getUrlEncoder().withoutPadding().encodeToString(expected);
        assertEquals(expectedDigest, contentDigest(result));
    }

    @Test
    void shouldProduceDifferentDigestWhenOrderChanges() {
        var result1 = step.execute(contextWith(List.of("{\"a\":1}", "{\"b\":2}")));
        var result2 = step.execute(contextWith(List.of("{\"b\":2}", "{\"a\":1}")));

        assertSuccess(result1);
        assertSuccess(result2);
        assertNotEquals(contentDigest(result1), contentDigest(result2));
    }

    @Test
    void shouldThrowStepExceptionWhenCanonicalizedResourcesNotFound() {
        SigningContext context = SigningContext.builder().build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(List<String> canonicalizedResources) {
        return SigningContext.builder()
                .attribute(JsonCanonicalizationStep.CANONICALIZED_RESOURCES_KEY, canonicalizedResources)
                .build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private String contentDigest(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(ContentDigestStep.CONTENT_DIGEST_KEY, String.class).orElseThrow();
    }
}
