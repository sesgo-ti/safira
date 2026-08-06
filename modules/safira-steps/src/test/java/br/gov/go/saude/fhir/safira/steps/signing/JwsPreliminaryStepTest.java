/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JwsPreliminaryStepTest {

    private JwsPreliminaryStep step;

    @BeforeEach
    void setUp() {
        step = new JwsPreliminaryStep();
    }

    @Test
    void shouldBuildPreliminaryJwsWithPayloadAndSignaturesArray() {
        var context = contextWith("header-b64", "payload-b64", "signature-b64");

        var result = step.execute(context);

        assertSuccess(result);
        ObjectNode jws = jwsPreliminary(result);
        assertEquals("payload-b64", jws.get("payload").asText());
        assertTrue(jws.get("signatures").isArray());
        assertEquals(1, jws.get("signatures").size());
    }

    @Test
    void shouldIncludeProtectedAndSignatureInSignaturesEntry() {
        var context = contextWith("header-b64", "payload-b64", "signature-b64");

        var result = step.execute(context);

        assertSuccess(result);
        ObjectNode entry = (ObjectNode) jwsPreliminary(result).get("signatures").get(0);
        assertEquals("header-b64", entry.get("protected").asText());
        assertEquals("signature-b64", entry.get("signature").asText());
    }

    @Test
    void shouldNotIncludeUnprotectedHeaderInPreliminaryStructure() {
        var context = contextWith("header-b64", "payload-b64", "signature-b64");

        var result = step.execute(context);

        assertSuccess(result);
        ObjectNode entry = (ObjectNode) jwsPreliminary(result).get("signatures").get(0);
        assertFalse(entry.has("header"));
    }

    @Test
    void shouldThrowWhenProtectedHeaderMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, "p")
                .attribute(CryptoSigningStep.SIGNATURE_KEY, "s")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowWhenContentDigestMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, "h")
                .attribute(CryptoSigningStep.SIGNATURE_KEY, "s")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowWhenSignatureMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, "h")
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, "p")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(String protectedHeader, String payload, String signature) {
        return SigningContext.builder()
                .attribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, protectedHeader)
                .attribute(ContentDigestStep.CONTENT_DIGEST_KEY, payload)
                .attribute(CryptoSigningStep.SIGNATURE_KEY, signature)
                .build();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private ObjectNode jwsPreliminary(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(JwsPreliminaryStep.JWS_PRELIMINARY_KEY, ObjectNode.class).orElseThrow();
    }
}
