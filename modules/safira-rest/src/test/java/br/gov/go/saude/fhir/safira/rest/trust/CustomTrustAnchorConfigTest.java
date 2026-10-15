/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.trust;

import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Sistema: confirma que {@link CustomTrustAnchorConfig} realmente lê um certificado autoassinado
 * do diretório configurado e o expõe como âncora de confiança, substituindo o
 * {@code TrustMaterialSource} padrão (o acervo ICP-Brasil nem chega a ser carregado neste
 * contexto mínimo, só a configuração sob teste).
 */
@SpringBootTest(classes = CustomTrustAnchorConfig.class, webEnvironment = SpringBootTest.WebEnvironment.NONE)
class CustomTrustAnchorConfigTest {

    private static X509Certificate raizGerada;

    @DynamicPropertySource
    static void configurarRaizPersonalizada(DynamicPropertyRegistry registry) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Principal subject = new X500Principal("CN=Raiz Personalizada de Teste");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = Date.from(Instant.now().minusSeconds(60));
        Date notAfter = Date.from(Instant.now().plusSeconds(3600));

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                subject, serial, notBefore, notAfter, subject, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(keyPair.getPrivate());
        raizGerada = new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));

        Path diretorio = Files.createTempDirectory("safira-raiz-personalizada-teste");
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(raizGerada.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        Files.writeString(diretorio.resolve("raiz.pem"), pem);

        registry.add("safira.trust.custom-roots-dir", diretorio::toString);
    }

    @Autowired
    TrustMaterialSource trustMaterialSource;

    @Test
    void shouldExposeCertificateFromConfiguredDirectoryAsTrustAnchor() {
        TrustMaterial material = trustMaterialSource.current().orElseThrow();

        assertThat(material.hasAnchors()).isTrue();
        assertThat(material.anchors())
                .extracting(TrustAnchor::getTrustedCert)
                .containsExactly(raizGerada);
    }
}
