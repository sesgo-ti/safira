/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;

class SignatureCryptoVerificationStepTest {

    private static final long LEAF_START = 1_754_006_400L;
    private static final long CERT_END = 1_893_456_000L;

    private static final String PROTECTED_B64 = "eyJhbGciOiJSUzI1NiJ9"; // arbitrary base64url
    private static final String PAYLOAD_B64 = "eyJmb28iOiJiYXIifQ";
    private static final String SIGNING_INPUT = PROTECTED_B64 + "." + PAYLOAD_B64;

    private static KeyPair rsaKeyPair;
    private static KeyPair ecKeyPair;
    private static X509Certificate rsaLeafCert;
    private static X509Certificate ecLeafCert;
    private static byte[] rsaSignature;
    private static byte[] ecSignatureRaw; // r||s 64 bytes

    private SignatureCryptoVerificationStep step;

    @BeforeAll
    static void setUpKeys() throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPair caRsa = TestCertificates.rsaKeyPair(2048);
        X509Certificate ca = TestCertificates.buildCaCert(caRsa, "Ca",
                new Date(LEAF_START * 1000L), new Date(CERT_END * 1000L));

        rsaKeyPair = TestCertificates.rsaKeyPair(2048);
        rsaLeafCert = TestCertificates.buildLeafCert(rsaKeyPair, caRsa, ca, "LeafRsa",
                new Date(LEAF_START * 1000L), new Date(CERT_END * 1000L),
                TestCertificates.ICP_BRASIL_POLICY_OID);

        ecKeyPair = TestCertificates.ecKeyPair("secp256r1");
        ecLeafCert = TestCertificates.buildLeafCert(ecKeyPair, caRsa, ca, "LeafEc",
                new Date(LEAF_START * 1000L), new Date(CERT_END * 1000L),
                TestCertificates.ICP_BRASIL_POLICY_OID);

        // Build signatures over SIGNING_INPUT
        Signature rs = Signature.getInstance("SHA256withRSA");
        rs.initSign(rsaKeyPair.getPrivate());
        rs.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));
        rsaSignature = rs.sign();

        Signature es = Signature.getInstance("SHA256withECDSA");
        es.initSign(ecKeyPair.getPrivate());
        es.update(SIGNING_INPUT.getBytes(StandardCharsets.UTF_8));
        byte[] derEc = es.sign();
        ecSignatureRaw = derToRawRs(derEc);
    }

    @BeforeEach
    void setUp() {
        step = new SignatureCryptoVerificationStep();
    }

    @Test
    void shouldFailWhenEs256SignatureNot64Bytes() {
        ValidationContext ctx = baseContext("ES256", ecLeafCert, new byte[63]);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                assertFailure(result).code());
    }

    @Test
    void shouldFailWhenRs256WithEcPublicKey() {
        ValidationContext ctx = baseContext("RS256", ecLeafCert, rsaSignature);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                assertFailure(result).code());
    }

    @Test
    void shouldFailWhenEs256WithRsaPublicKey() {
        ValidationContext ctx = baseContext("ES256", rsaLeafCert, ecSignatureRaw);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                assertFailure(result).code());
    }

    @Test
    void shouldFailWhenSignatureTampered() {
        byte[] tampered = rsaSignature.clone();
        tampered[0] ^= 0x01;
        ValidationContext ctx = baseContext("RS256", rsaLeafCert, tampered);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertEquals(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                assertFailure(result).code());
    }

    @Test
    void shouldVerifyValidRs256Signature() {
        ValidationContext ctx = baseContext("RS256", rsaLeafCert, rsaSignature);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertInstanceOf(StepResult.Success.class, result);
    }

    @Test
    void shouldVerifyValidEs256Signature() {
        ValidationContext ctx = baseContext("ES256", ecLeafCert, ecSignatureRaw);

        StepResult<ValidationContext> result = step.execute(ctx);

        assertInstanceOf(StepResult.Success.class, result);
    }

    @Test
    void shouldThrowStepExceptionWhenUnsupportedAlgorithm() {
        ValidationContext ctx = baseContext("NONE", rsaLeafCert, rsaSignature);

        assertThrows(StepException.class, () -> step.execute(ctx));
    }

    // ===== Helpers =====

    private static ValidationContext baseContext(String alg, X509Certificate cert, byte[] signatureBytes) {
        Map<String, Object> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put("alg", alg);
        return ValidationContext.builder()
                .protectedHeader(protectedHeader)
                .rawProtectedHeaderBase64Url(PROTECTED_B64)
                .payloadBase64Url(PAYLOAD_B64)
                .signatureBytes(signatureBytes)
                .certificateChain(List.of(cert))
                .build();
    }

    private static StepResult.Failure<ValidationContext> assertFailure(StepResult<ValidationContext> r) {
        return assertInstanceOf(StepResult.Failure.class, r);
    }

    /**
     * Converts a DER-encoded ECDSA signature (ASN.1 SEQUENCE of 2 INTEGERs)
     * into fixed-length r||s raw form (32 bytes each for P-256).
     */
    private static byte[] derToRawRs(byte[] der) {
        // der: 0x30 len 0x02 rLen r 0x02 sLen s
        int offset = 2;
        if ((der[1] & 0x80) != 0) {
            offset = 2 + (der[1] & 0x7F);
        }
        // r
        int rLen = der[offset + 1];
        int rStart = offset + 2;
        byte[] r = new byte[rLen];
        System.arraycopy(der, rStart, r, 0, rLen);
        // s
        int sOffset = rStart + rLen;
        int sLen = der[sOffset + 1];
        int sStart = sOffset + 2;
        byte[] s = new byte[sLen];
        System.arraycopy(der, sStart, s, 0, sLen);

        byte[] rPadded = padTo32(r);
        byte[] sPadded = padTo32(s);
        byte[] raw = new byte[64];
        System.arraycopy(rPadded, 0, raw, 0, 32);
        System.arraycopy(sPadded, 0, raw, 32, 32);
        return raw;
    }

    private static byte[] padTo32(byte[] v) {
        if (v.length == 32) return v;
        if (v.length > 32) {
            // strip leading zeros (present when high bit is set)
            byte[] out = new byte[32];
            System.arraycopy(v, v.length - 32, out, 0, 32);
            return out;
        }
        byte[] out = new byte[32];
        System.arraycopy(v, 0, out, 32 - v.length, v.length);
        return out;
    }

    @SuppressWarnings("unused")
    private static String b64UrlNoPad(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
