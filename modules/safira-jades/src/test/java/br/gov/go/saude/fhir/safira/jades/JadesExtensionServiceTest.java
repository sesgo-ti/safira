/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/** Extensão JAdES-B-B → B-T da política 0.2.0: {@code etsiU} em claro com um único {@code sigTst}. */
class JadesExtensionServiceTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";
    private static final String TSA_POLICY = "1.2.3.4.5.6";

    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static String bb;
    private static String bt;

    @BeforeAll
    static void extendOnce() throws Exception {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        JadesSigningService signing = new JadesSigningService();
        JadesSigningSession session = signing.newSession(new JadesSigningService.Request(pki.chain(),
                MessageDigest.getInstance("SHA-256").digest("x".getBytes(StandardCharsets.UTF_8)),
                Instant.now().getEpochSecond(), POLICY_URI));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pki.leafKeys.getPrivate());
        signer.update(signing.dataToSign(session));
        bb = signing.sign(session, signer.sign());

        bt = new JadesExtensionService().extendToBaselineT(bb, TspSources.online(tsa.url(), 10, TSA_POLICY));
    }

    @AfterAll
    static void stopTsa() {
        tsa.close();
    }

    @Test
    void shouldProduceClearEtsiUWithSingleSigTst() throws Exception {
        JsonNode header = MAPPER.readTree(bt).get("signatures").get(0).get("header");

        String structure = header.toString().replaceAll("\"val\":\"[^\"]+\"", "\"val\":\"V\"");
        assertThat(structure).isEqualTo("{\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":\"V\"}]}}]}");
    }

    @Test
    void shouldEncodeTimestampTokenInStandardBase64() throws Exception {
        String val = MAPPER.readTree(bt).get("signatures").get(0).get("header")
                .get("etsiU").get(0).get("sigTst").get("tstTokens").get(0).get("val").asText();

        TimeStampToken token = new TimeStampToken(new CMSSignedData(Base64.getDecoder().decode(val)));
        assertThat(token.getTimeStampInfo().getPolicy().getId()).isEqualTo(TSA_POLICY);
        assertThat(token.getTimeStampInfo().getNonce()).isNotNull();
    }

    @Test
    void shouldComputeImprintAsSha256OfSignatureText() throws Exception {
        JsonNode signature = MAPPER.readTree(bt).get("signatures").get(0);
        String val = signature.get("header").get("etsiU").get(0).get("sigTst").get("tstTokens").get(0).get("val").asText();
        TimeStampToken token = new TimeStampToken(new CMSSignedData(Base64.getDecoder().decode(val)));

        byte[] expected = MessageDigest.getInstance("SHA-256")
                .digest(signature.get("signature").asText().getBytes(StandardCharsets.US_ASCII));
        assertThat(token.getTimeStampInfo().getMessageImprintAlgOID()).isEqualTo(NISTObjectIdentifiers.id_sha256);
        assertThat(token.getTimeStampInfo().getMessageImprintDigest()).isEqualTo(expected);
    }

    @Test
    void shouldKeepBaselineBComponentsUnchanged() throws Exception {
        JsonNode original = MAPPER.readTree(bb);
        JsonNode extended = MAPPER.readTree(bt);

        assertThat(extended.get("payload")).isEqualTo(original.get("payload"));
        assertThat(extended.get("signatures").get(0).get("protected"))
                .isEqualTo(original.get("signatures").get(0).get("protected"));
        assertThat(extended.get("signatures").get(0).get("signature"))
                .isEqualTo(original.get("signatures").get(0).get("signature"));
    }

    @Test
    void shouldBeClassifiedAsJadesBaselineTByDss() {
        var verifier = CertificateVerifiers.create(List.of(pki.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspGoodFor(pki.leafCert), pki.ocspGoodFor(tsa.tsaCert()))),
                EvidenceRevocationSources.crlFromEvidence(List.of(pki.crl())));

        Reports reports = new JadesValidationService().validate(bt, verifier);
        String id = reports.getSimpleReport().getFirstSignatureId();

        assertThat(reports.getSimpleReport().getIndication(id)).isEqualTo(Indication.TOTAL_PASSED);
        assertThat(reports.getSimpleReport().getSignatureFormat(id)).isEqualTo(SignatureLevel.JAdES_BASELINE_T);
    }
}
