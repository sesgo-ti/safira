/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Helper for building X.509 certificate fixtures for validation step tests.
 */
final class TestCertificates {

    static final String ICP_BRASIL_POLICY_OID = "2.16.76.1.2.1.1";
    private static final AtomicLong SERIAL = new AtomicLong(1000);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestCertificates() {
    }

    static KeyPair rsaKeyPair(int keySize) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keySize);
        return kpg.generateKeyPair();
    }

    static KeyPair ecKeyPair(String curveName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        kpg.initialize(new ECGenParameterSpec(curveName));
        return kpg.generateKeyPair();
    }

    static X509Certificate buildCaCert(KeyPair caKp, String cn, Date notBefore, Date notAfter)
            throws Exception {
        X500Name name = new X500Name("CN=" + cn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, name, caKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    static X509Certificate buildLeafCert(KeyPair leafKp, KeyPair caKp, X509Certificate caCert,
                                         String cn, Date notBefore, Date notAfter,
                                         String policyOid) throws Exception {
        return buildLeafCert(leafKp, caKp, caCert, cn, notBefore, notAfter, policyOid,
                "SHA256withRSA");
    }

    static X509Certificate buildLeafCert(KeyPair leafKp, KeyPair caKp, X509Certificate caCert,
                                         String cn, Date notBefore, Date notAfter,
                                         String policyOid, String signatureAlg) throws Exception {
        X500Name subject = new X500Name("CN=" + cn);
        X500Name issuer = new X500Name(caCert.getSubjectX500Principal().getName());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, subject, leafKp.getPublic());
        if (policyOid != null) {
            PolicyInformation[] policies = new PolicyInformation[]{
                    new PolicyInformation(new ASN1ObjectIdentifier(policyOid))
            };
            builder.addExtension(Extension.certificatePolicies, false,
                    new CertificatePolicies(policies));
        }
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        ContentSigner signer = new JcaContentSignerBuilder(signatureAlg)
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(caKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    static String sha256Hex(X509Certificate cert) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        return HexFormat.of().formatHex(md.digest(cert.getEncoded()));
    }
}
