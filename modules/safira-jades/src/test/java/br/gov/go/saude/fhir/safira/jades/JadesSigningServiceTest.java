/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.LeafProfile;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.jades.JAdESUtils;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Round-trip JAdES-B-B da política 0.2.0: sessão → dataToSign → assinatura externa (JCA) →
 * montagem — verificado contra o schema oficial ETSI (specs-jades) e contra o validador do
 * EU DSS (oráculo de conformidade).
 */
class JadesSigningServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";
    private static final long REFERENCE_TIMESTAMP = 1755000000L;

    private static TestPki pki;
    private static JadesSigningService service;
    private static String jws;
    private static byte[] payload;

    @BeforeAll
    static void signOnce() throws Exception {
        pki = TestPki.create();
        service = new JadesSigningService();

        payload = MessageDigest.getInstance("SHA-256")
                .digest("conteudo-canonicalizado-de-teste".getBytes(StandardCharsets.UTF_8));

        JadesSigningSession session = service.newSession(new JadesSigningService.Request(
                pki.chain(), payload, REFERENCE_TIMESTAMP, POLICY_URI));

        byte[] dataToSign = service.dataToSign(session);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pki.leafKeys.getPrivate());
        signer.update(dataToSign);

        jws = service.sign(session, signer.sign());
    }

    @Test
    void shouldProduceGeneralJsonSerializationWithAttachedPayload() throws Exception {
        JsonNode root = MAPPER.readTree(jws);

        List<String> members = new ArrayList<>();
        root.fieldNames().forEachRemaining(members::add);
        assertThat(members).containsExactlyInAnyOrder("payload", "signatures");
        assertThat(root.get("signatures")).hasSize(1);
        List<String> signatureMembers = new ArrayList<>();
        root.get("signatures").get(0).fieldNames().forEachRemaining(signatureMembers::add);
        assertThat(signatureMembers).containsExactlyInAnyOrder("protected", "signature");
        assertThat(root.get("payload").asText())
                .isEqualTo(Base64.getUrlEncoder().withoutPadding().encodeToString(payload));
    }

    @Test
    void shouldEmitExactlyTheProtectedHeaderOfPolicy020() throws Exception {
        JsonNode header = decodeProtectedHeader(jws);

        List<String> members = new ArrayList<>();
        header.fieldNames().forEachRemaining(members::add);
        assertThat(members).containsExactlyInAnyOrder("alg", "x5t#S256", "x5c", "iat", "sigPId", "srCms");
        assertThat(header.get("alg").asText()).isEqualTo("RS256");
        assertThat(header.get("iat").asLong()).isEqualTo(REFERENCE_TIMESTAMP);
        assertThat(header.get("sigPId").toString()).isEqualTo("{\"id\":{\"id\":\"" + POLICY_URI + "\"}}");
        assertThat(header.get("srCms").toString())
                .isEqualTo("[{\"commId\":{\"id\":\"urn:oid:1.2.840.10065.1.12.1.5\"}}]");
    }

    @Test
    void shouldReferenceSigningCertificateBySha256Thumbprint() throws Exception {
        JsonNode header = decodeProtectedHeader(jws);

        String expected = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(MessageDigest.getInstance("SHA-256").digest(pki.leafCert.getEncoded()));
        assertThat(header.get("x5t#S256").asText()).isEqualTo(expected);
    }

    @Test
    void shouldCarryFullChainInX5cWithStandardBase64() throws Exception {
        JsonNode header = decodeProtectedHeader(jws);

        assertThat(header.get("x5c")).hasSize(2);
        assertThat(header.get("x5c").get(0).asText())
                .isEqualTo(Base64.getEncoder().encodeToString(pki.leafCert.getEncoded()));
        assertThat(header.get("x5c").get(1).asText())
                .isEqualTo(Base64.getEncoder().encodeToString(pki.caCert.getEncoded()));
    }

    @Test
    void shouldConformToOfficialEtsiSchema() {
        assertThat(JAdESUtils.getInstance().validateAgainstSchema(jws)).isEmpty();
    }

    @Test
    void shouldBeClassifiedAsJadesBaselineBByDss() {
        CommonCertificateVerifier verifier = CertificateVerifiers.create(
                List.of(pki.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspGoodFor(pki.leafCert))),
                EvidenceRevocationSources.crlFromEvidence(List.of(pki.crl())));

        Reports reports = new JadesValidationService().validate(jws, verifier);
        String signatureId = reports.getSimpleReport().getFirstSignatureId();

        assertThat(reports.getSimpleReport().getIndication(signatureId)).isEqualTo(Indication.TOTAL_PASSED);
        assertThat(reports.getSimpleReport().getSignatureFormat(signatureId)).isEqualTo(SignatureLevel.JAdES_BASELINE_B);
    }

    @Test
    void shouldRejectNonRsaSigningCertificate() {
        TestPki ec = TestPki.create(LeafProfile.a3().withKey("EC", 0));

        assertThatThrownBy(() -> service.newSession(new JadesSigningService.Request(
                ec.chain(), payload, REFERENCE_TIMESTAMP, POLICY_URI)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldTranscodeEcdsaConcatToDerSequence() {
        byte[] rs = new byte[64];
        new SecureRandom().nextBytes(rs);

        byte[] der = EcdsaSignatureFormats.concatToDer(rs);

        assertThat(der[0]).isEqualTo((byte) 0x30);
        assertThat(ASN1Sequence.getInstance(der).size()).isEqualTo(2);
    }

    private static JsonNode decodeProtectedHeader(String jwsJson) throws Exception {
        JsonNode root = MAPPER.readTree(jwsJson);
        String protectedB64 = root.get("signatures").get(0).get("protected").asText();
        byte[] decoded = Base64.getUrlDecoder().decode(protectedB64);
        return MAPPER.readTree(new String(decoded, StandardCharsets.UTF_8));
    }
}
