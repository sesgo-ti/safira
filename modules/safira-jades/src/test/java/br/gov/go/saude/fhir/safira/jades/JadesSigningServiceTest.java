/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;
import eu.europa.esig.jades.JAdESUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Round-trip JAdES-B-B: sessão → dataToSign → assinatura externa (JCA) → montagem —
 * verificado contra o schema oficial ETSI (specs-jades) e contra o validador do EU DSS
 * (oráculo de conformidade).
 */
class JadesSigningServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";
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
                pki.chain(), payload, REFERENCE_TIMESTAMP, POLICY_URI, null, null));

        byte[] dataToSign = service.dataToSign(session);

        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pki.leafKeys.getPrivate());
        signer.update(dataToSign);

        jws = service.sign(session, signer.sign());
    }

    @Test
    void deveProduzirGeneralJsonSerializationComPayloadAttached() throws Exception {
        JsonNode root = MAPPER.readTree(jws);

        assertThat(root.has("payload")).isTrue();
        assertThat(root.has("signatures")).isTrue();
        assertThat(root.get("signatures")).hasSize(1);
        assertThat(root.get("signatures").get(0).has("protected")).isTrue();
        assertThat(root.get("signatures").get(0).has("signature")).isTrue();

        String expectedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(payload);
        assertThat(root.get("payload").asText()).isEqualTo(expectedPayload);
    }

    @Test
    void protectedHeaderDeveSerMinimoConformeIgSesGo() throws Exception {
        JsonNode header = decodeProtectedHeader(jws);

        assertThat(header.get("alg").asText()).isEqualTo("RS256");
        assertThat(header.get("x5c")).hasSize(2);
        // iat incondicional (ETSI TS 119 182-1 §5.1.11) com o instante declarado
        assertThat(header.get("iat").asLong()).isEqualTo(REFERENCE_TIMESTAMP);
        // sigPId.id é um objeto oId (§5.4.1): {"id": {"id": "<uri>"}}
        assertThat(header.get("sigPId").get("id").get("id").asText()).isEqualTo(POLICY_URI);
    }

    @Test
    void deveSerConformeAoSchemaOficialEtsi() {
        List<String> violations = JAdESUtils.getInstance().validateAgainstSchema(jws);
        assertThat(violations).isEmpty();
    }

    @Test
    void oraculoDssDeveRetornarTotalPassed() {
        CommonCertificateVerifier verifier = CertificateVerifiers.create(
                List.of(pki.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspGoodFor(pki.leafCert))),
                EvidenceRevocationSources.crlFromEvidence(List.of(pki.crl())));

        Reports reports = new JadesValidationService().validate(jws, verifier);
        String signatureId = reports.getSimpleReport().getFirstSignatureId();

        assertThat(reports.getSimpleReport().getIndication(signatureId))
                .as("SimpleReport: %s", reports.getSimpleReport().getJaxbModel())
                .isEqualTo(Indication.TOTAL_PASSED);
    }

    @Test
    void transcodificacaoEcdsaConcatParaDerDeveProduzirSequenceValida() throws Exception {
        byte[] rs = new byte[64];
        java.security.SecureRandom.getInstanceStrong().nextBytes(rs);
        byte[] der = EcdsaSignatureFormats.concatToDer(rs);

        assertThat(der[0]).isEqualTo((byte) 0x30);
        var seq = org.bouncycastle.asn1.ASN1Sequence.getInstance(der);
        assertThat(seq.size()).isEqualTo(2);
    }

    private static JsonNode decodeProtectedHeader(String jwsJson) throws Exception {
        JsonNode root = MAPPER.readTree(jwsJson);
        String protectedB64 = root.get("signatures").get(0).get("protected").asText();
        byte[] decoded = Base64.getUrlDecoder().decode(protectedB64);
        return MAPPER.readTree(new String(decoded, StandardCharsets.UTF_8));
    }
}
