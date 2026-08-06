/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

/**
 * Fixture compartilhado de certificados X.509 para testes de assinatura e validação.
 *
 * <p>Gera uma cadeia mínima válida conforme as exigências dos steps do engine:
 * <ul>
 *   <li>CA auto-assinada com BasicConstraints(CA=true) e RSA 2048</li>
 *   <li>Leaf assinado pela CA com política ICP-Brasil (OID 2.16.76.1.2.1.1),
 *       KeyUsage (digitalSignature + nonRepudiation) e CPF no SubjectAlternativeName</li>
 * </ul>
 *
 * <p>O {@code TrustStoreService} é mockado nos testes com {@code isTrustedRoot(any()) → true},
 * dispensando qualquer configuração de hash da CA no trust store.
 */
final class IcpBrasilCertificateFixture {

    // notBefore igual ao minimumCertificateDate para satisfazer chain-validation e validation-chain-validation
    static final long CERT_START = 1751328000L; // 2025-07-01T00:00:00Z
    static final long CERT_END   = 4102444800L; // 2100-01-01T00:00:00Z

    static final String TEST_CPF = "12345678901";

    static final KeyPair CA_KEYS;
    static final X509Certificate CA_CERT;
    static final KeyPair LEAF_KEYS;
    static final X509Certificate LEAF_CERT;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        try {
            CA_KEYS = generateRsaKeyPair();
            CA_CERT = buildCaCert(CA_KEYS, "CN=Test Root CA");

            LEAF_KEYS = generateRsaKeyPair();
            LEAF_CERT = buildLeafCert(LEAF_KEYS, CA_KEYS, CA_CERT, "CN=Test Signer", TEST_CPF);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private IcpBrasilCertificateFixture() {}

    static String toPemBase64(KeyPair keys) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pem = new JcaPEMWriter(writer)) {
            pem.writeObject(keys.getPrivate());
        }
        return Base64.getEncoder().encodeToString(writer.toString().getBytes(StandardCharsets.UTF_8));
    }

    static String toBase64(X509Certificate cert) throws Exception {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static X509Certificate buildCaCert(KeyPair caKeys, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKeys.getPrivate());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                name, caKeys.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static X509Certificate buildLeafCert(KeyPair leafKeys, KeyPair caKeys,
                                                   X509Certificate caCert, String dn,
                                                   String cpf) throws Exception {
        X500Name subject = new X500Name(dn);
        X500Name issuer  = new X500Name(caCert.getSubjectX500Principal().getName());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKeys.getPrivate());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(System.nanoTime()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                subject, leafKeys.getPublic());

        builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation[]{
                        new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.2.1.1"))
                }));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        // Formato ICP-Brasil: DDMMYYYY(8) + CPF(11) + complemento
        String cpfContent = "01011990" + cpf + "000000000000000000";
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
        vec.add(new DERTaggedObject(true, 0, new DERUTF8String(cpfContent)));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(vec))));

        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

}
