/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;

class ValidationChainBuildStepTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private ValidationChainBuildStep step;

    @BeforeEach
    void setUp() {
        step = new ValidationChainBuildStep();
    }

    @Test
    void shouldBuildChainInOrderFromX5c() throws Exception {
        X509Certificate leaf = newSelfSignedCert("CN=Leaf");
        X509Certificate root = newSelfSignedCert("CN=Root");
        String leafB64 = Base64.getEncoder().encodeToString(leaf.getEncoded());
        String rootB64 = Base64.getEncoder().encodeToString(root.getEncoded());

        ValidationContext ctx = contextWithX5c(List.of(leafB64, rootB64));

        StepResult<ValidationContext> result = step.execute(ctx);

        StepResult.Success<ValidationContext> success =
                assertInstanceOf(StepResult.Success.class, result);
        List<X509Certificate> chain = success.context().getCertificateChain().orElseThrow();
        assertEquals(2, chain.size());
        assertEquals(leaf, chain.get(0));
        assertEquals(root, chain.get(1));
    }

    @Test
    void shouldFailWhenAnyCertBase64Invalid() throws Exception {
        X509Certificate leaf = newSelfSignedCert("CN=Leaf");
        String leafB64 = Base64.getEncoder().encodeToString(leaf.getEncoded());
        ValidationContext ctx = contextWithX5c(List.of(leafB64, "!!!not-base64!!!"));

        StepResult<ValidationContext> result = step.execute(ctx);

        StepResult.Failure<ValidationContext> failure =
                assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(SignatureExceptionCode.FORMAT_BASE64_INVALID, failure.code());
    }

    @Test
    void shouldFailWhenAnyCertNotValidDer() {
        String bogus = Base64.getEncoder().encodeToString(new byte[]{0x01, 0x02, 0x03, 0x04});
        ValidationContext ctx = contextWithX5c(List.of(bogus));

        StepResult<ValidationContext> result = step.execute(ctx);

        StepResult.Failure<ValidationContext> failure =
                assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(SignatureExceptionCode.CERT_INVALID_FORMAT, failure.code());
    }

    // ===== Helpers =====

    private static ValidationContext contextWithX5c(List<String> x5c) {
        Map<String, Object> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put("alg", "RS256");
        protectedHeader.put("x5c", x5c);
        return ValidationContext.builder()
                .protectedHeader(protectedHeader)
                .build();
    }

    private static X509Certificate newSelfSignedCert(String cn) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        X500Name name = new X500Name(cn);
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 86_400_000L);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }
}
