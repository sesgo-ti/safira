/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.simulador;

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
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HexFormat;
import java.util.concurrent.atomic.AtomicLong;

/**
 * PKI fictícia **gerada do zero a cada subida** da aplicação, ativa só com o profile
 * {@code simulado}. Nenhuma chave fica fixa no código-fonte nem no artefato: a CA, o
 * certificado-folha (perfil A3 da política 0.2.0) e as chaves são gerados em memória na
 * construção deste bean e descartados quando a aplicação para.
 *
 * <p>O CPF usado no SAN é o de exemplo amplamente reutilizado em documentação e testes
 * brasileiros ("52998224725"), nunca o de uma pessoa real.</p>
 */
public final class SimuladorPki {

    private static final String TEST_CPF = "52998224725";
    private static final String POLICY_OID_A3 = "2.16.76.1.2.3.1";
    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private final KeyPair caKeys;
    private final X509Certificate caCert;
    private final KeyPair leafKeys;
    private final X509Certificate leafCert;

    public SimuladorPki() {
        try {
            this.caKeys = generateRsaKeyPair();
            this.caCert = buildCa(caKeys);
            this.leafKeys = generateRsaKeyPair();
            this.leafCert = buildLeaf(leafKeys, caKeys, caCert);
        } catch (NoSuchAlgorithmException | OperatorCreationException | CertificateException | IOException e) {
            throw new IllegalStateException("Falha ao gerar PKI do simulador", e);
        }
    }

    public X509Certificate caCert() {
        return caCert;
    }

    /** OID de política do certificado-folha gerado, usado para montar a allowlist em tempo de execução. */
    public String oid() {
        return POLICY_OID_A3;
    }

    /** SHA-256 (hex minúsculo) do DER da CA fictícia, recalculado a cada subida, nunca fixo. */
    public String issuerSha256() {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(caCert.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    public String leafCertPem() {
        return toPem(leafCert);
    }

    public String leafKeyPem() {
        return toPem(leafKeys.getPrivate());
    }

    /** Resposta OCSP {@code GOOD} (DER de {@code OCSPResponse}) para o certificado informado, assinada pela CA fictícia. */
    public byte[] ocspGoodFor(X509Certificate subject) {
        try {
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);

            CertificateID certId = new CertificateID(
                    digests.get(CertificateID.HASH_SHA1), caHolder, subject.getSerialNumber());

            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(caHolder.getSubject()));
            Instant now = Instant.now();
            Instant nextUpdate = now.plus(3650, ChronoUnit.DAYS);
            builder.addResponse(certId, CertificateStatus.GOOD, Date.from(now), Date.from(nextUpdate), null);

            BasicOCSPResp basic = builder.build(signer(caKeys), new X509CertificateHolder[]{caHolder}, Date.from(now));
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        } catch (OperatorCreationException | CertificateEncodingException | OCSPException | IOException e) {
            throw new IllegalStateException("Falha ao gerar resposta OCSP do simulador", e);
        }
    }

    private static KeyPair generateRsaKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static ContentSigner signer(KeyPair keys) throws OperatorCreationException {
        return new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keys.getPrivate());
    }

    private static X509Certificate buildCa(KeyPair caKeys)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        X500Name name = new X500Name("CN=Safira Simulador Root CA (efêmera)");
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(730, ChronoUnit.DAYS));
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(SERIAL.incrementAndGet()), notBefore, notAfter, name, caKeys.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(caKeys.getPublic()));
        return convert(builder.build(signer(caKeys)));
    }

    private static X509Certificate buildLeaf(KeyPair leafKeys, KeyPair caKeys, X509Certificate caCert)
            throws OperatorCreationException, CertificateException, IOException, NoSuchAlgorithmException {
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.DAYS));
        Date notAfter = Date.from(now.plus(730, ChronoUnit.DAYS));
        X500Name subject = new X500Name("CN=Simulador de Teste:" + TEST_CPF + ",SERIALNUMBER=" + TEST_CPF);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Name(caCert.getSubjectX500Principal().getName()),
                BigInteger.valueOf(SERIAL.incrementAndGet()), notBefore, notAfter, subject, leafKeys.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation[]{new PolicyInformation(new ASN1ObjectIdentifier(POLICY_OID_A3))}));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        // otherName ICP-Brasil 2.16.76.1.3.1: DDMMYYYY + CPF + complemento
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
        vec.add(new DERTaggedObject(true, 0, new DERUTF8String("01011990" + TEST_CPF + "000000000000000000")));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(vec))));

        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(leafKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        return convert(builder.build(signer(caKeys)));
    }

    private static X509Certificate convert(X509CertificateHolder holder) throws CertificateException {
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }

    private static String toPem(Object obj) {
        try {
            StringWriter writer = new StringWriter();
            try (JcaPEMWriter pem = new JcaPEMWriter(writer)) {
                pem.writeObject(obj);
            }
            return writer.toString();
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao serializar PEM", e);
        }
    }
}
