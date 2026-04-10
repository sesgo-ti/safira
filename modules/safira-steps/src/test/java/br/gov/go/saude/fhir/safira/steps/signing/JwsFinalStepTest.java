package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.steps.signing.revocation.RevocationEvidence;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HexFormat;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwsFinalStepTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JwsFinalStep step;

    @BeforeEach
    void setUp() {
        step = new JwsFinalStep();
    }

    @Test
    void shouldBuildFinalJwsWithOcspRefsForIatStrategy() throws Exception {
        String hexHash = "a".repeat(128); // 64 bytes em hex
        var evidences = List.of(new RevocationEvidence("OCSP", "der-base64", hexHash));
        var context = iatContext(preliminaryJws(), evidences);

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode jws = MAPPER.readTree(jwsFinal(result));
        JsonNode header = jws.get("signatures").get(0).get("header");
        assertNotNull(header);
        assertTrue(header.has("rRefs"));
        JsonNode rRefs = header.get("rRefs");
        assertTrue(rRefs.has("ocspRefs"));
        assertFalse(rRefs.has("crlRefs"));
        assertEquals(1, rRefs.get("ocspRefs").size());

        String expectedDigestB64 = Base64.getEncoder().encodeToString(HexFormat.of().parseHex(hexHash));
        assertEquals(expectedDigestB64, rRefs.get("ocspRefs").get(0).get("digestValue").asText());
        assertEquals("http://www.w3.org/2001/04/xmlenc#sha512",
                rRefs.get("ocspRefs").get(0).get("digestAlg").asText());
    }

    @Test
    void shouldBuildFinalJwsWithCrlRefsForIatStrategy() throws Exception {
        String hexHash = "b".repeat(128);
        var evidences = List.of(new RevocationEvidence("CRL", "der-base64", hexHash));
        var context = iatContext(preliminaryJws(), evidences);

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode jws = MAPPER.readTree(jwsFinal(result));
        JsonNode rRefs = jws.get("signatures").get(0).get("header").get("rRefs");
        assertTrue(rRefs.has("crlRefs"));
        assertFalse(rRefs.has("ocspRefs"));
    }

    @Test
    void shouldBuildFinalJwsWithBothOcspAndCrlRefs() throws Exception {
        String hexHash = "c".repeat(128);
        var evidences = List.of(
                new RevocationEvidence("OCSP", "der1", hexHash),
                new RevocationEvidence("CRL", "der2", hexHash));
        var context = iatContext(preliminaryJws(), evidences);

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode rRefs = MAPPER.readTree(jwsFinal(result)).get("signatures").get(0).get("header").get("rRefs");
        assertTrue(rRefs.has("ocspRefs"));
        assertTrue(rRefs.has("crlRefs"));
    }

    @Test
    void shouldIncludeSigTstForTsaStrategy() throws Exception {
        String hexHash = "d".repeat(128);
        var evidences = List.of(new RevocationEvidence("OCSP", "der", hexHash));
        var context = tsaContext(preliminaryJws(), evidences, "token-tsa-base64");

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode header = MAPPER.readTree(jwsFinal(result)).get("signatures").get(0).get("header");
        assertEquals("token-tsa-base64", header.get("sigTst").asText());
        assertTrue(header.has("rRefs"));
    }

    @Test
    void shouldNotIncludeHeaderWhenNoEvidencesAndIatStrategy() throws Exception {
        var context = iatContext(preliminaryJws(), List.of());

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode signatureEntry = MAPPER.readTree(jwsFinal(result)).get("signatures").get(0);
        assertFalse(signatureEntry.has("header"));
    }

    @Test
    void shouldProduceCompactJsonWithoutWhitespace() throws Exception {
        var context = iatContext(preliminaryJws(), List.of());

        var result = step.execute(context);

        assertSuccess(result);
        String jsonString = jwsFinal(result);
        assertFalse(jsonString.contains("\n"));
        assertFalse(jsonString.contains("  "));
    }

    @Test
    void shouldThrowWhenPreliminaryJwsMissing() {
        SigningContext context = SigningContext.builder()
                .strategy(TimestampStrategy.IAT)
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowWhenTsaTokenMissingForTsaStrategy() {
        SigningContext context = SigningContext.builder()
                .strategy(TimestampStrategy.TSA)
                .attribute(JwsPreliminaryStep.JWS_PRELIMINARY_KEY, preliminaryJws())
                .attribute(ChainValidationStep.REVOCATION_EVIDENCES_KEY, List.of())
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private ObjectNode preliminaryJws() {
        ObjectNode jws = MAPPER.createObjectNode();
        jws.put("payload", "payload-b64");
        ObjectNode entry = jws.putArray("signatures").addObject();
        entry.put("protected", "header-b64");
        entry.put("signature", "signature-b64");
        return jws;
    }

    private SigningContext iatContext(ObjectNode jws, List<RevocationEvidence> evidences) {
        return SigningContext.builder()
                .strategy(TimestampStrategy.IAT)
                .attribute(JwsPreliminaryStep.JWS_PRELIMINARY_KEY, jws)
                .attribute(ChainValidationStep.REVOCATION_EVIDENCES_KEY, evidences)
                .build();
    }

    private SigningContext tsaContext(ObjectNode jws, List<RevocationEvidence> evidences, String tsaToken) {
        return SigningContext.builder()
                .strategy(TimestampStrategy.TSA)
                .attribute(JwsPreliminaryStep.JWS_PRELIMINARY_KEY, jws)
                .attribute(ChainValidationStep.REVOCATION_EVIDENCES_KEY, evidences)
                .attribute(TsaTimestampStep.TSA_TOKEN_KEY, tsaToken)
                .build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private String jwsFinal(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(JwsFinalStep.JWS_FINAL_KEY, String.class).orElseThrow();
    }
}
