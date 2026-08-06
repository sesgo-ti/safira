/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class ProtectedHeaderStepTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // 2025-07-01 to 2030-01-01
    private static final long CERT_START = 1751328000L;
    private static final long CERT_END = 1893456000L;
    private static final long REF_TS = 1754006400L; // 2025-08-01 (inside cert validity)

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private ProtectedHeaderStep step;

    @BeforeEach
    void setUp() {
        step = new ProtectedHeaderStep();
    }

    // ===== Happy path RSA + IAT =====

    @Test
    void shouldBuildProtectedHeaderWithRsaAndIatStrategy() throws Exception {
        KeyPair rsaKeys = generateRsaKeyPair(2048);
        X509Certificate cert = generateCert(rsaKeys, "CN=Test Signer");
        var context = contextWithIat(cert, REF_TS);

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode header = decodeHeader(result);
        assertEquals("RS256", header.get("alg").asText());
        assertTrue(header.has("x5c"));
        assertTrue(header.has("iat"));
        assertEquals(REF_TS, header.get("iat").asLong());
        assertTrue(header.has("sigPId"));
        assertEquals("https://example.com/policy|1.0.0", header.get("sigPId").get("id").asText());
    }

    // ===== Happy path ECC + TSA =====

    @Test
    void shouldBuildProtectedHeaderWithEcAndTsaStrategy() throws Exception {
        KeyPair ecKeys = generateEcKeyPair();
        X509Certificate cert = generateCert(ecKeys, "CN=Test EC Signer");
        var context = contextWithTsa(cert);

        var result = step.execute(context);

        assertSuccess(result);
        JsonNode header = decodeHeader(result);
        assertEquals("ES256", header.get("alg").asText());
        assertTrue(header.has("x5c"));
        assertFalse(header.has("iat"));
        assertTrue(header.has("sigPId"));
    }

    // ===== Key validation =====

    @Test
    void shouldReturnWeakKeyWhenRsaKeyTooSmall() throws Exception {
        KeyPair rsaKeys = generateRsaKeyPair(1024);
        X509Certificate cert = generateCert(rsaKeys, "CN=Weak RSA");
        var context = contextWithIat(cert, REF_TS);

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.CERT_WEAK_KEY);
    }

    // ===== Base64Url encoding =====

    @Test
    void shouldProduceValidBase64UrlWithoutPadding() throws Exception {
        KeyPair rsaKeys = generateRsaKeyPair(2048);
        X509Certificate cert = generateCert(rsaKeys, "CN=Test");
        var context = contextWithIat(cert, REF_TS);

        var result = step.execute(context);

        assertSuccess(result);
        String protectedHeader = getProtectedHeader(result);
        assertFalse(protectedHeader.contains("="));
        assertFalse(protectedHeader.contains("+"));
        assertFalse(protectedHeader.contains("/"));
    }

    // ===== Helpers =====

    private SigningContext contextWithIat(X509Certificate cert, long refTs) throws Exception {
        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        return SigningContext.builder()
                .certificateChain(new X509Certificate[]{cert})
                .rawCertificateChain(List.of(certB64))
                .strategy(TimestampStrategy.IAT)
                .referenceTimestamp(refTs)
                .policyIdentifierUri("https://example.com/policy|1.0.0")
                .build();
    }

    private SigningContext contextWithTsa(X509Certificate cert) throws Exception {
        String certB64 = Base64.getEncoder().encodeToString(cert.getEncoded());
        return SigningContext.builder()
                .certificateChain(new X509Certificate[]{cert})
                .rawCertificateChain(List.of(certB64))
                .strategy(TimestampStrategy.TSA)
                .referenceTimestamp(REF_TS)
                .policyIdentifierUri("https://example.com/policy|1.0.0")
                .build();
    }

    private KeyPair generateRsaKeyPair(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);
        return gen.generateKeyPair();
    }

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        return gen.generateKeyPair();
    }

    private X509Certificate generateCert(KeyPair keys, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        String sigAlg = keys.getPublic().getAlgorithm().equals("RSA")
                ? "SHA256WithRSA" : "SHA256WithECDSA";
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(keys.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                name, keys.getPublic());
        return new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private void assertFailure(StepResult<SigningContext> result,
                                SignatureExceptionCode expectedCode) {
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expectedCode, ((StepResult.Failure<SigningContext>) result).code());
    }

    private String getProtectedHeader(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, String.class)
                .orElseThrow();
    }

    private JsonNode decodeHeader(StepResult<SigningContext> result) throws Exception {
        String b64 = getProtectedHeader(result);
        String json = new String(Base64.getUrlDecoder().decode(b64), StandardCharsets.UTF_8);
        return MAPPER.readTree(json);
    }
}
