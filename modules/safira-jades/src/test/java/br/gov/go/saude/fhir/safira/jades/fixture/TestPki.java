/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.fixture;

import com.sun.net.httpserver.HttpServer;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CertificatePolicies;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.PolicyInformation;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.cms.SignerInfoGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.CollectionStore;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

/**
 * PKI de teste completa para os cenários JAdES:
 *
 * <ul>
 *   <li>CA raiz auto-assinada (RSA 2048, keyCertSign|cRLSign, SKI);</li>
 *   <li>certificado de signatário (política ICP-Brasil, digitalSignature|nonRepudiation,
 *       CPF no SAN, AKI/SKI);</li>
 *   <li>certificado de TSA (EKU id-kp-timeStamping crítico) emitido pela mesma CA;</li>
 *   <li>respostas OCSP {@code GOOD} e CRL assinadas pela CA (evidências LTV);</li>
 *   <li>{@link FakeTsa}: TSA RFC 3161 real servida em HTTP local — permite testar
 *       B-T/B-LT/B-LTA sem qualquer serviço externo.</li>
 * </ul>
 */
public final class TestPki {

    public static final long CERT_START = 1751328000L; // 2025-07-01T00:00:00Z
    public static final long CERT_END = 4102444800L;   // 2100-01-01T00:00:00Z
    public static final String TEST_CPF = "12345678901";

    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());

    public final KeyPair caKeys;
    public final X509Certificate caCert;
    public final KeyPair leafKeys;
    public final X509Certificate leafCert;
    public final KeyPair tsaKeys;
    public final X509Certificate tsaCert;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TestPki(KeyPair caKeys, X509Certificate caCert,
                    KeyPair leafKeys, X509Certificate leafCert,
                    KeyPair tsaKeys, X509Certificate tsaCert) {
        this.caKeys = caKeys;
        this.caCert = caCert;
        this.leafKeys = leafKeys;
        this.leafCert = leafCert;
        this.tsaKeys = tsaKeys;
        this.tsaCert = tsaCert;
    }

    public static TestPki create() {
        try {
            KeyPair caKeys = rsa();
            X509Certificate caCert = buildCa(caKeys, "CN=Safira Test Root CA");

            KeyPair leafKeys = rsa();
            X509Certificate leafCert = buildLeaf(leafKeys, caKeys, caCert, "CN=Safira Test Signer");

            KeyPair tsaKeys = rsa();
            X509Certificate tsaCert = buildTsa(tsaKeys, caKeys, caCert, "CN=Safira Test TSA");

            return new TestPki(caKeys, caCert, leafKeys, leafCert, tsaKeys, tsaCert);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao montar PKI de teste", e);
        }
    }

    public List<X509Certificate> chain() {
        return List.of(leafCert, caCert);
    }

    /** Chave privada do signatário em PEM (PKCS#8), codificada em Base64 — formato aceito pelo crypto-signing. */
    public String leafKeyPemBase64() {
        try {
            java.io.StringWriter writer = new java.io.StringWriter();
            try (org.bouncycastle.openssl.jcajce.JcaPEMWriter pem =
                         new org.bouncycastle.openssl.jcajce.JcaPEMWriter(writer)) {
                pem.writeObject(leafKeys.getPrivate());
            }
            return java.util.Base64.getEncoder()
                    .encodeToString(writer.toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao serializar chave privada em PEM", e);
        }
    }

    /** Resposta OCSP {@code GOOD} (DER de {@code OCSPResponse}) para o certificado informado, assinada pela CA. */
    public byte[] ocspGoodFor(X509Certificate subject) {
        try {
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);

            CertificateID certId = new CertificateID(
                    digests.get(CertificateID.HASH_SHA1), caHolder, subject.getSerialNumber());

            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(caHolder.getSubject()));
            Date now = new Date();
            Date nextUpdate = new Date(now.getTime() + 10L * 365 * 24 * 3600 * 1000);
            builder.addResponse(certId, CertificateStatus.GOOD, now, nextUpdate, null);

            BasicOCSPResp basic = builder.build(
                    signer(caKeys), new X509CertificateHolder[]{caHolder}, now);
            OCSPResp resp = new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic);
            return resp.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar resposta OCSP de teste", e);
        }
    }

    /** CRL vazia (nenhum revogado) assinada pela CA, com nextUpdate distante. */
    public byte[] crl() {
        try {
            Date now = new Date();
            X509v2CRLBuilder builder = new X509v2CRLBuilder(
                    new X500Name(caCert.getSubjectX500Principal().getName()), now);
            builder.setNextUpdate(new Date(now.getTime() + 10L * 365 * 24 * 3600 * 1000));
            return builder.build(signer(caKeys)).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar CRL de teste", e);
        }
    }

    /** Sobe uma TSA RFC 3161 local (HTTP) usando o certificado de TSA desta PKI. */
    public FakeTsa startFakeTsa() {
        return new FakeTsa(tsaKeys, tsaCert);
    }

    /**
     * TSA RFC 3161 mínima e determinística sobre {@link HttpServer} local.
     *
     * <p>Aceita {@code application/timestamp-query}, responde
     * {@code application/timestamp-reply} com token assinado pelo certificado de TSA
     * (EKU id-kp-timeStamping). Fecha com {@link #close()}.
     */
    public static final class FakeTsa implements AutoCloseable {

        private final HttpServer server;

        private FakeTsa(KeyPair tsaKeys, X509Certificate tsaCert) {
            try {
                this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                server.createContext("/tsa", exchange -> {
                    try (exchange) {
                        byte[] requestBytes = exchange.getRequestBody().readAllBytes();
                        TimeStampRequest request = new TimeStampRequest(requestBytes);
                        TimeStampResponse response = respond(request, tsaKeys, tsaCert);
                        byte[] body = response.getEncoded();
                        exchange.getResponseHeaders().set("Content-Type", "application/timestamp-reply");
                        exchange.sendResponseHeaders(200, body.length);
                        try (OutputStream out = exchange.getResponseBody()) {
                            out.write(body);
                        }
                    } catch (Exception e) {
                        exchange.sendResponseHeaders(500, -1);
                    }
                });
                server.start();
            } catch (Exception e) {
                throw new IllegalStateException("Falha ao subir TSA fake", e);
            }
        }

        public String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort() + "/tsa";
        }

        @Override
        public void close() {
            server.stop(0);
        }

        private static TimeStampResponse respond(TimeStampRequest request,
                                                 KeyPair tsaKeys,
                                                 X509Certificate tsaCert) throws Exception {
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            SignerInfoGenerator signerInfo = new JcaSignerInfoGeneratorBuilder(digests)
                    .build(signer(tsaKeys), tsaCert);

            TimeStampTokenGenerator tokenGen = new TimeStampTokenGenerator(
                    signerInfo,
                    digests.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    new ASN1ObjectIdentifier("1.3.6.1.4.1.13762.3"));
            tokenGen.addCertificates(new CollectionStore<>(
                    List.of(new JcaX509CertificateHolder(tsaCert))));

            TimeStampResponseGenerator responseGen =
                    new TimeStampResponseGenerator(tokenGen, TSPAlgorithms.ALLOWED);
            return responseGen.generate(request, BigInteger.valueOf(SERIAL.incrementAndGet()), new Date());
        }
    }

    // ------------------------------------------------------------------
    // Construção de certificados
    // ------------------------------------------------------------------

    private static KeyPair rsa() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private static ContentSigner signer(KeyPair keys) {
        try {
            return new JcaContentSignerBuilder("SHA256WithRSA")
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(keys.getPrivate());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate buildCa(KeyPair caKeys, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(SERIAL.incrementAndGet()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                name, caKeys.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign | KeyUsage.digitalSignature));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(caKeys.getPublic()));
        return convert(builder.build(signer(caKeys)));
    }

    private static X509Certificate buildLeaf(KeyPair leafKeys, KeyPair caKeys,
                                             X509Certificate caCert, String dn) throws Exception {
        JcaX509v3CertificateBuilder builder = baseIssuedCert(leafKeys, caCert, dn);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.certificatePolicies, false,
                new CertificatePolicies(new PolicyInformation[]{
                        new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.2.1.1"))
                }));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));

        // otherName ICP-Brasil OID 2.16.76.1.3.1: DDMMYYYY(8) + CPF(11) + complemento
        String cpfContent = "01011990" + TEST_CPF + "000000000000000000";
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
        vec.add(new DERTaggedObject(true, 0, new DERUTF8String(cpfContent)));
        builder.addExtension(Extension.subjectAlternativeName, false,
                new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(vec))));

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(leafKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        return convert(builder.build(signer(caKeys)));
    }

    private static X509Certificate buildTsa(KeyPair tsaKeys, KeyPair caKeys,
                                            X509Certificate caCert, String dn) throws Exception {
        JcaX509v3CertificateBuilder builder = baseIssuedCert(tsaKeys, caCert, dn);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        // RFC 3161 §2.3: EKU id-kp-timeStamping, marcado crítico
        builder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(tsaKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        return convert(builder.build(signer(caKeys)));
    }

    private static JcaX509v3CertificateBuilder baseIssuedCert(KeyPair subjectKeys,
                                                              X509Certificate caCert,
                                                              String dn) {
        return new JcaX509v3CertificateBuilder(
                new X500Name(caCert.getSubjectX500Principal().getName()),
                BigInteger.valueOf(SERIAL.incrementAndGet()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                new X500Name(dn), subjectKeys.getPublic());
    }

    private static X509Certificate convert(X509CertificateHolder holder) throws Exception {
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(holder);
    }
}
