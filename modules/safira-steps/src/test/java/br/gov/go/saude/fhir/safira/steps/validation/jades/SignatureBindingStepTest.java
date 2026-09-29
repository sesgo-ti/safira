/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SignatureBindingStepTest {

    private static SigningResult signed;
    private static ValidationContext valid;

    @BeforeAll
    static void setUp() {
        TestPki pki = TestPki.create();
        signed = SignedArtifactFixture.sign(pki, TestConfigs.policy(pki));
        valid = SignedArtifactFixture.validationContext(signed);
    }

    private static StepResult<ValidationContext> run(ValidationContext context) {
        return new SignatureBindingStep().execute(context);
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    /** Aplica a mesma alteração à Signature de entrada e à cópia em Provenance.signature. */
    private static ValidationContext withSignature(JsonObject signature) {
        return valid.toBuilder()
                .signatureJson(signature)
                .provenanceJson(valid.getProvenanceJson().with("signature", new JsonArray(List.of(signature))))
                .build();
    }

    @Test
    void shouldExposeDecodedJws() {
        StepResult<ValidationContext> result = run(valid);

        assertThat(result.isSuccess()).isTrue();
        String expected = new String(Base64.getDecoder().decode(
                LosslessJson.parseObject(signed.signatureJson()).string("data").orElseThrow()), StandardCharsets.UTF_8);
        assertThat(result.context().getAttribute(ValidationKeys.JWS_JSON, String.class)).contains(expected);
    }

    @Test
    void shouldRejectWrongSigFormat() {
        assertThat(code(run(withSignature(valid.getSignatureJson().with("sigFormat", new JsonString("application/jose"))))))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectAuthorSignatureType() {
        JsonObject type = LosslessJson.parseObject("{\"system\":\"urn:iso-astm:E1762-95:2013\",\"code\":\"1.2.840.10065.1.12.1.1\"}");

        assertThat(code(run(withSignature(valid.getSignatureJson().with("type", new JsonArray(List.of(type)))))))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectNonCanonicalBase64Data() {
        String data = valid.getSignatureJson().string("data").orElseThrow();

        assertThat(code(run(withSignature(valid.getSignatureJson().with("data", new JsonString(data + "\n"))))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldRejectSignatureDiffersFromProvenanceSignature() {
        ValidationContext context = valid.toBuilder()
                .signatureJson(valid.getSignatureJson().with("when", new JsonString("2030-01-01T00:00:00Z")))
                .build();

        assertThat(code(run(context))).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectProvenanceWithoutSignature() {
        ValidationContext context = valid.toBuilder().provenanceJson(valid.getProvenanceJson().without("signature")).build();

        assertThat(code(run(context))).isEqualTo(SignatureExceptionCode.FORMAT_SIGNATURE_MISSING);
    }

    @Test
    void shouldRejectProvenanceWithTwoSignatures() {
        JsonObject signature = valid.getSignatureJson();
        ValidationContext context = valid.toBuilder()
                .provenanceJson(valid.getProvenanceJson().with("signature", new JsonArray(List.of(signature, signature))))
                .build();

        assertThat(code(run(context))).isEqualTo(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID);
    }

    @Test
    void shouldRejectWhenNoAgentMatchesSigner() {
        ValidationContext context = valid.toBuilder().provenanceJson(valid.getProvenanceJson().without("agent")).build();

        assertThat(code(run(context))).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }
}
