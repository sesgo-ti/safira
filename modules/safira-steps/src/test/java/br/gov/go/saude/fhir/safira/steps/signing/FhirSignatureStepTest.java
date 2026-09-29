/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class FhirSignatureStepTest {

    private static final String JWS = "{\"payload\":\"p\",\"signatures\":[{\"protected\":\"h\",\"signature\":\"s\"}]}";
    private static final long IAT = 1790000000L;
    private static final SignerIdentity SIGNER =
            new SignerIdentity(CertificateType.A3, SignerIdentity.CPF_SYSTEM, "52998224725");
    private static final String PROVENANCE = "{\"resourceType\":\"Provenance\",\"target\":[{\"reference\":\"urn:uuid:x\"}],"
            + "\"recorded\":\"2026-01-01T00:00:00Z\",\"agent\":[{\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\","
            + "\"value\":\"52998224725\"}}}],\"extension\":[{\"url\":\"u\",\"valueDecimal\":1.50}]}";

    private static SigningContext context(String provenance) {
        return SigningContext.builder()
                .provenanceJson(LosslessJson.parseObject(provenance))
                .referenceTimestamp(IAT)
                .attribute("jwsFinal", JWS)
                .attribute(CertificatePolicyStep.SIGNER_IDENTITY_KEY, SIGNER)
                .build();
    }

    private static SigningResult result(StepResult<SigningContext> step) {
        assertThat(step.isSuccess()).isTrue();
        return step.context().getSigningResult();
    }

    @Test
    void shouldMapSignatureElementsOfPolicy020() {
        JsonObject signature = LosslessJson.parseObject(result(new FhirSignatureStep().execute(context(PROVENANCE))).signatureJson());

        assertThat(LosslessJson.write(signature.get("type").orElseThrow()))
                .isEqualTo("[{\"system\":\"urn:iso-astm:E1762-95:2013\",\"code\":\"1.2.840.10065.1.12.1.5\"}]");
        assertThat(signature.string("sigFormat")).contains("application/jose+json");
        assertThat(signature.string("targetFormat")).contains("application/fhir+json");
        assertThat(LosslessJson.write(signature.get("who").orElseThrow()))
                .isEqualTo("{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"52998224725\"}}");
        assertThat(new String(Base64.getDecoder().decode(signature.string("data").orElseThrow()), StandardCharsets.UTF_8))
                .isEqualTo(JWS);
    }

    @Test
    void shouldDeriveWhenFromIat() {
        JsonObject signature = LosslessJson.parseObject(result(new FhirSignatureStep().execute(context(PROVENANCE))).signatureJson());

        assertThat(signature.string("when")).contains("2026-09-21T14:13:20Z");
    }

    @Test
    void shouldReplaceSignatureInProvenanceCopyPreservingOtherMembers() {
        SigningResult result = result(new FhirSignatureStep().execute(context(
                PROVENANCE.replace("}]}}}],", "}]}}}],\"signature\":[{\"data\":\"antiga\"}],"))));

        JsonObject provenance = LosslessJson.parseObject(result.provenanceJson());
        assertThat(provenance.array("signature").orElseThrow().items())
                .containsExactly(LosslessJson.parseObject(result.signatureJson()));
        assertThat(result.provenanceJson()).contains("\"valueDecimal\":1.50").contains("\"recorded\":\"2026-01-01T00:00:00Z\"");
    }

    @Test
    void shouldNotMutateInputProvenance() {
        SigningContext context = context(PROVENANCE);

        new FhirSignatureStep().execute(context);

        assertThat(LosslessJson.write(context.getProvenanceJson())).isEqualTo(PROVENANCE);
    }

    @Test
    void shouldFailWhenNoAgentMatchesSigner() {
        StepResult<SigningContext> result = new FhirSignatureStep()
                .execute(context(PROVENANCE.replace("\"value\":\"52998224725\"", "\"value\":\"11144477735\"")));

        assertThat(((StepResult.Failure<SigningContext>) result).code())
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }
}
