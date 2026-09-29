/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;

class JwsStructureStepTest {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static String bb;
    private static String bt;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        var policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
        bb = jwsOf(SignedArtifactFixture.sign(pki, policy).signatureJson());
        bt = jwsOf(SignedArtifactFixture.sign(pki, policy, Instant.now().getEpochSecond(), tsa).signatureJson());
    }

    @AfterAll
    static void stop() {
        tsa.close();
    }

    private static String jwsOf(String signatureJson) {
        return new String(Base64.getDecoder().decode(LosslessJson.parseObject(signatureJson).string("data").orElseThrow()),
                StandardCharsets.UTF_8);
    }

    private static StepResult<ValidationContext> run(String jws) {
        return new JwsStructureStep().execute(ValidationContext.builder().attribute(ValidationKeys.JWS_JSON, jws).build());
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    /** Recoloca um protected header alterado (a assinatura deixa de conferir, mas a estrutura é o alvo). */
    private static String withHeader(String jws, String headerJson) {
        JsonObject root = LosslessJson.parseObject(jws);
        String protectedB64 = ((JsonObject) root.array("signatures").orElseThrow().items().getFirst())
                .string("protected").orElseThrow();
        return jws.replace(protectedB64, URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)));
    }

    private static String header(String jws) {
        JsonObject root = LosslessJson.parseObject(jws);
        String protectedB64 = ((JsonObject) root.array("signatures").orElseThrow().items().getFirst())
                .string("protected").orElseThrow();
        return new String(Base64.getUrlDecoder().decode(protectedB64), StandardCharsets.UTF_8);
    }

    @Test
    void shouldIdentifyBaselineB() {
        StepResult<ValidationContext> result = run(bb);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class)).contains(JadesLevel.B_B);
        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.leafCert, pki.caCert);
    }

    @Test
    void shouldIdentifyBaselineT() {
        assertThat(run(bt).context().getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class)).contains(JadesLevel.B_T);
    }

    @Test
    void shouldRejectDuplicateMemberInProtectedHeader() {
        String h = header(bb);

        assertThat(code(run(withHeader(bb, h.replace("\"alg\":\"RS256\"", "\"alg\":\"RS256\",\"alg\":\"RS256\"")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldRejectHeaderWithCrit() {
        assertThat(code(run(withHeader(bb, header(bb).replaceFirst("\\{", "{\"crit\":[\"sigPId\"],")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldRejectSigDInProtectedHeader() {
        assertThat(code(run(withHeader(bb, header(bb).replaceFirst("\\{", "{\"sigD\":{},")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_COMPONENT_PLACEMENT_INVALID);
    }

    @Test
    void shouldRejectAlgorithmOtherThanRs256() {
        assertThat(code(run(withHeader(bb, header(bb).replace("\"alg\":\"RS256\"", "\"alg\":\"ES256\"")))))
                .isEqualTo(SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM);
    }

    @Test
    void shouldRejectMissingIat() {
        assertThat(code(run(withHeader(bb, header(bb).replaceAll(",?\"iat\":\\d+", "")))))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_MISSING);
    }

    @Test
    void shouldRejectOtherSignaturePolicy() {
        assertThat(code(run(withHeader(bb, header(bb).replace("politica/0.2.0", "politica/0.1.0")))))
                .isEqualTo(SignatureExceptionCode.POLICY_SIGNATURE_POLICY_ID_INVALID);
    }

    @Test
    void shouldRejectOtherCommitmentType() {
        assertThat(code(run(withHeader(bb, header(bb).replace("1.2.840.10065.1.12.1.5", "1.2.840.10065.1.12.1.1")))))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectThumbprintOfOtherCertificate() {
        String h = header(bb);
        String thumbprint = LosslessJson.parseObject(h).string("x5t#S256").orElseThrow();

        assertThat(code(run(withHeader(bb, h.replace(thumbprint, URL.encodeToString(new byte[32]))))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldRejectChainWhoseIssuerHasSameNameButOtherKey() throws Exception {
        // Toda PKI de teste usa o mesmo DN de CA: só a assinatura distingue o emissor verdadeiro
        String h = header(bb);
        String realCa = Base64.getEncoder().encodeToString(pki.caCert.getEncoded());
        String otherCa = Base64.getEncoder().encodeToString(TestPki.create().caCert.getEncoded());

        assertThat(code(run(withHeader(bb, h.replace(realCa, otherCa)))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldRejectExtraTopLevelMember() {
        assertThat(code(run(bb.replaceFirst("\\{", "{\"extra\":1,")))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }

    @Test
    void shouldRejectEmptyUnprotectedHeader() {
        assertThat(code(run(bb.replace("\"protected\":", "\"header\":{},\"protected\":"))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID);
    }

    @Test
    void shouldRejectBase64UrlEncodedEtsiUComponent() {
        String opaque = bt.replaceAll("\"etsiU\":\\[\\{.*?\\}\\]\\}\\}\\]", "\"etsiU\":[\"eyJ4IjoxfQ\"]");

        assertThat(code(run(opaque))).isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID);
    }

    @Test
    void shouldRejectPaddedPayload() {
        String payload = LosslessJson.parseObject(bb).string("payload").orElseThrow();

        assertThat(code(run(bb.replace("\"" + payload + "\"", "\"" + payload + "=\""))))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED);
    }
}
