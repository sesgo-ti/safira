/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.timestamp;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.TokenOptions;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TrustStoreRef;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TimestampTokenInspectorTest {

    private static final String SIGNATURE_TEXT = "c2lnbmF0dXJl";
    private static final long IAT = 1790000000L;
    private static final TsaPolicy POLICY = new TsaPolicy(TestPki.TSA_POLICY_OID, 1L, new TrustStoreRef("unused"));

    private static TestPki pki;
    private static byte[] imprint;

    @BeforeAll
    static void setUp() throws Exception {
        pki = TestPki.create();
        imprint = MessageDigest.getInstance("SHA-256").digest(SIGNATURE_TEXT.getBytes(StandardCharsets.US_ASCII));
    }

    private static Date at(long epochSeconds) {
        return Date.from(Instant.ofEpochSecond(epochSeconds));
    }

    private static Optional<SignatureExceptionCode> verify(TokenOptions options) {
        TimestampTokenInspector.Inspection inspection =
                TimestampTokenInspector.inspect(pki.timestampToken(imprint, options));
        return TimestampTokenInspector.verify(inspection, SIGNATURE_TEXT, IAT, POLICY, pki.chain(), Long.MAX_VALUE)
                .map(PolicyViolation::code);
    }

    @Test
    void shouldAcceptConformingToken() {
        assertThat(verify(TokenOptions.at(at(IAT + 10)))).isEmpty();
    }

    @Test
    void shouldExposeTokenFields() {
        TimestampTokenInspector.Inspection inspection = TimestampTokenInspector.inspect(
                pki.timestampToken(imprint, TokenOptions.at(at(IAT)).withAccuracy(1)));

        assertThat(inspection.policyOid()).isEqualTo(TestPki.TSA_POLICY_OID);
        assertThat(inspection.genTime()).isEqualTo(Instant.ofEpochSecond(IAT));
        assertThat(inspection.accuracySeconds()).isEqualTo(1L);
        assertThat(inspection.tsaCertificate()).isEqualTo(pki.tsaCert);
    }

    @Test
    void shouldRejectTokenOutsideIatWindow() {
        assertThat(verify(TokenOptions.at(at(IAT + 300)))).contains(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS);
    }

    @Test
    void shouldUseConfiguredMaximumAccuracyWhenTokenOmitsIt() {
        // genTime + max(1 s) = iat + 300 ainda está dentro; iat + 300 + 1 não
        assertThat(verify(TokenOptions.at(at(IAT + 299)))).isEmpty();
        assertThat(verify(TokenOptions.at(at(IAT - 300)))).contains(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS);
    }

    @Test
    void shouldRejectAccuracyAboveMaximum() {
        assertThat(verify(TokenOptions.at(at(IAT)).withAccuracy(2))).contains(SignatureExceptionCode.TSA_INVALID_TOKEN);
    }

    @Test
    void shouldRejectUnexpectedPolicy() {
        assertThat(verify(TokenOptions.at(at(IAT)).withPolicy("1.2.3.9"))).contains(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED);
    }

    @Test
    void shouldRejectNonCriticalEku() {
        TimestampTokenInspector.Inspection valid =
                TimestampTokenInspector.inspect(pki.timestampToken(imprint, TokenOptions.at(at(IAT))));
        TimestampTokenInspector.Inspection nonCritical = new TimestampTokenInspector.Inspection(valid.policyOid(),
                valid.genTime(), valid.accuracyMicros(), pki.tsaCertWithNonCriticalEku(), valid.tokenCertificates(),
                valid.token());

        assertThat(TimestampTokenInspector.verify(nonCritical, SIGNATURE_TEXT, IAT, POLICY, pki.chain(), Long.MAX_VALUE)
                .map(PolicyViolation::code)).contains(SignatureExceptionCode.TSA_CERTIFICATE_PURPOSE_INVALID);
    }

    @Test
    void shouldRejectImprintOfOtherSignature() {
        TimestampTokenInspector.Inspection inspection =
                TimestampTokenInspector.inspect(pki.timestampToken(imprint, TokenOptions.at(at(IAT))));

        assertThat(TimestampTokenInspector.verify(inspection, "outra", IAT, POLICY, pki.chain(), Long.MAX_VALUE)
                .map(PolicyViolation::code)).contains(SignatureExceptionCode.TSA_MESSAGE_IMPRINT_MISMATCH);
    }

    @Test
    void shouldRejectTokenIntervalAfterUpperBound() {
        TimestampTokenInspector.Inspection inspection =
                TimestampTokenInspector.inspect(pki.timestampToken(imprint, TokenOptions.at(at(IAT))));

        assertThat(TimestampTokenInspector.verify(inspection, SIGNATURE_TEXT, IAT, POLICY, pki.chain(), IAT)
                .map(PolicyViolation::code)).contains(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS);
    }

    @Test
    void shouldRejectMalformedToken() {
        assertThatThrownBy(() -> TimestampTokenInspector.inspect(new byte[]{1, 2, 3}))
                .isInstanceOf(TimestampTokenException.class)
                .extracting(e -> ((TimestampTokenException) e).getCode())
                .isEqualTo(SignatureExceptionCode.TSA_INVALID_TOKEN);
    }

    @Test
    void shouldExtractTokenFromClearEtsiU() {
        byte[] token = pki.timestampToken(imprint, TokenOptions.at(at(IAT)));
        String jws = "{\"payload\":\"p\",\"signatures\":[{\"protected\":\"h\",\"header\":{\"etsiU\":[{\"sigTst\":"
                + "{\"tstTokens\":[{\"val\":\"" + Base64.getEncoder().encodeToString(token) + "\"}]}}]},\"signature\":\"s\"}]}";

        assertThat(TimestampTokenInspector.tokenFromJws(jws)).isEqualTo(token);
    }

    @Test
    void shouldRejectJwsWithoutEtsiU() {
        assertThatThrownBy(() -> TimestampTokenInspector.tokenFromJws(
                "{\"payload\":\"p\",\"signatures\":[{\"protected\":\"h\",\"signature\":\"s\"}]}"))
                .isInstanceOf(TimestampTokenException.class);
    }

    @Test
    void shouldCoverSignerChainValidityInInterval() {
        TimestampTokenInspector.Inspection inspection =
                TimestampTokenInspector.inspect(pki.timestampToken(imprint, TokenOptions.at(at(TestPki.CERT_START - 100))));

        assertThat(TimestampTokenInspector.verify(inspection, SIGNATURE_TEXT, TestPki.CERT_START - 100, POLICY,
                List.of(pki.leafCert), Long.MAX_VALUE).map(PolicyViolation::code))
                .contains(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS);
    }
}
