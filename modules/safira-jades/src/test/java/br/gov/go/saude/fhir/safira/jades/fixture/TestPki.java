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
import org.bouncycastle.tsp.TimeStampRequestGenerator;
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
    public static final String TEST_CPF = "52998224725";
    public static final String TEST_CNPJ = "11222333000181";
    /** OID de política TSA usado pela {@link FakeTsa} quando a requisição não informa {@code reqPolicy}. */
    public static final String TSA_POLICY_OID = "1.3.6.1.4.1.13762.3";

    /**
     * Perfil do certificado folha gerado.
     *
     * @param policyOid   OID em certificatePolicies
     * @param keyUsage    bits de KeyUsage (constantes de {@link KeyUsage})
     * @param subjectDn   DN do titular
     * @param sanOid      OID do otherName ICP-Brasil no SAN (nulo omite o SAN)
     * @param sanValue    conteúdo do otherName
     * @param keyAlgorithm {@code RSA} ou {@code EC}
     * @param rsaBits     tamanho da chave RSA
     */
    public record LeafProfile(String policyOid, int keyUsage, String subjectDn, String sanOid,
                              String sanValue, String keyAlgorithm, int rsaBits) {

        /** A3 conforme a política 0.2.0: RSA-2048, digitalSignature, CPF em SERIALNUMBER e SAN. */
        public static LeafProfile a3() {
            return new LeafProfile("2.16.76.1.2.3.1", KeyUsage.digitalSignature | KeyUsage.nonRepudiation,
                    "CN=Fulano de Tal:" + TEST_CPF + ",SERIALNUMBER=" + TEST_CPF,
                    "2.16.76.1.3.1", "01011990" + TEST_CPF + "000000000000000000", "RSA", 2048);
        }

        /** SE-S (selo): RSA-2048, digitalSignature, CNPJ em SERIALNUMBER e SAN. */
        public static LeafProfile seS() {
            return new LeafProfile("2.16.76.1.2.201.1", KeyUsage.digitalSignature,
                    "CN=Estabelecimento Teste:" + TEST_CNPJ + ",SERIALNUMBER=" + TEST_CNPJ,
                    "2.16.76.1.3.3", TEST_CNPJ, "RSA", 2048);
        }

        public LeafProfile withPolicyOid(String oid) {
            return new LeafProfile(oid, keyUsage, subjectDn, sanOid, sanValue, keyAlgorithm, rsaBits);
        }

        public LeafProfile withKeyUsage(int bits) {
            return new LeafProfile(policyOid, bits, subjectDn, sanOid, sanValue, keyAlgorithm, rsaBits);
        }

        public LeafProfile withSubjectDn(String dn) {
            return new LeafProfile(policyOid, keyUsage, dn, sanOid, sanValue, keyAlgorithm, rsaBits);
        }

        public LeafProfile withSan(String oid, String value) {
            return new LeafProfile(policyOid, keyUsage, subjectDn, oid, value, keyAlgorithm, rsaBits);
        }

        public LeafProfile withKey(String algorithm, int bits) {
            return new LeafProfile(policyOid, keyUsage, subjectDn, sanOid, sanValue, algorithm, bits);
        }
    }

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
        return create(LeafProfile.a3());
    }

    public static TestPki create(LeafProfile profile) {
        try {
            KeyPair caKeys = rsa();
            X509Certificate caCert = buildCa(caKeys, "CN=Safira Test Root CA");

            KeyPair leafKeys = "EC".equals(profile.keyAlgorithm()) ? ec() : rsa(profile.rsaBits());
            X509Certificate leafCert = buildLeaf(leafKeys, caKeys, caCert, profile);

            KeyPair tsaKeys = rsa();
            X509Certificate tsaCert = buildTsa(tsaKeys, caKeys, caCert, "CN=Safira Test TSA");

            return new TestPki(caKeys, caCert, leafKeys, leafCert, tsaKeys, tsaCert);
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao montar PKI de teste", e);
        }
    }

    /** SHA-256 (hex minúsculo) do DER da CA — valor de {@code issuerSha256} na allowlist. */
    public String issuerSha256() {
        try {
            return java.util.HexFormat.of().formatHex(
                    java.security.MessageDigest.getInstance("SHA-256").digest(caCert.getEncoded()));
        } catch (Exception e) {
            throw new IllegalStateException(e);
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

    /**
     * Opções de um {@code TimeStampToken} gerado diretamente (sem HTTP).
     *
     * @param policyOid        OID de política do TSTInfo
     * @param genTime          instante do carimbo
     * @param accuracySeconds  accuracy em segundos (nulo omite o campo)
     */
    public record TokenOptions(String policyOid, Date genTime, Integer accuracySeconds) {

        public static TokenOptions at(Date genTime) {
            return new TokenOptions(TSA_POLICY_OID, genTime, null);
        }

        public TokenOptions withPolicy(String oid) {
            return new TokenOptions(oid, genTime, accuracySeconds);
        }

        public TokenOptions withAccuracy(Integer seconds) {
            return new TokenOptions(policyOid, genTime, seconds);
        }
    }

    /** Certificado da TSA com EKU id-kp-timeStamping NÃO crítico (mesma chave da TSA de teste). */
    public X509Certificate tsaCertWithNonCriticalEku() {
        try {
            return buildTsaCertificate(tsaKeys, caKeys, caCert, "CN=Safira Test TSA", null, false);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * {@code TimeStampToken} (CMS ContentInfo DER) sobre o hash SHA-256 informado, assinado por
     * um certificado de TSA emitido pela CA desta PKI.
     */
    public byte[] timestampToken(byte[] sha256Imprint, TokenOptions options) {
        try {
            X509Certificate certificate = tsaCert;
            DigestCalculatorProvider digests = new JcaDigestCalculatorProviderBuilder()
                    .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
            SignerInfoGenerator signerInfo = new JcaSignerInfoGeneratorBuilder(digests)
                    .build(signer(tsaKeys), certificate);
            TimeStampTokenGenerator generator = new TimeStampTokenGenerator(signerInfo,
                    digests.get(new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
                    new ASN1ObjectIdentifier(options.policyOid()));
            if (options.accuracySeconds() != null) {
                generator.setAccuracySeconds(options.accuracySeconds());
            }
            generator.addCertificates(new CollectionStore<>(List.of(new JcaX509CertificateHolder(certificate))));
            TimeStampRequestGenerator requestGenerator = new TimeStampRequestGenerator();
            requestGenerator.setCertReq(true);
            TimeStampRequest request = requestGenerator.generate(TSPAlgorithms.SHA256, sha256Imprint,
                    BigInteger.valueOf(SERIAL.incrementAndGet()));
            return generator.generate(request, BigInteger.valueOf(SERIAL.incrementAndGet()), options.genTime())
                    .getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao gerar TimeStampToken de teste", e);
        }
    }

    /** Sobe uma TSA RFC 3161 local (HTTP) com responder OCSP próprio (AIA no certificado da TSA). */
    public FakeTsa startFakeTsa() {
        return new FakeTsa(this);
    }

    /**
     * TSA RFC 3161 mínima e determinística sobre {@link HttpServer} local.
     *
     * <p>Serve dois endpoints:
     * <ul>
     *   <li>{@code /tsa} — aceita {@code application/timestamp-query} e responde token
     *       RFC 3161 assinado por um certificado de TSA (EKU id-kp-timeStamping) emitido
     *       pela CA da PKI, contendo extensão AIA apontando para o responder local;</li>
     *   <li>{@code /ocsp} — responder OCSP que responde {@code GOOD} (assinado pela CA)
     *       para qualquer certificado consultado, ecoando o nonce quando presente.</li>
     * </ul>
     *
     * <p>Permite exercitar B-T, B-LT e B-LTA sem qualquer serviço externo: a extensão LT
     * obtém a revogação do certificado da TSA pelo AIA — resolvido neste mesmo servidor.
     */
    public static final class FakeTsa implements AutoCloseable {

        private final HttpServer server;
        private final KeyPair tsaKeys;
        private final X509Certificate tsaCert;

        private FakeTsa(TestPki pki) {
            try {
                this.server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
                int port = server.getAddress().getPort();

                this.tsaKeys = rsa();
                this.tsaCert = buildTsaWithAia(tsaKeys, pki.caKeys, pki.caCert,
                        "CN=Safira Fake TSA", "http://127.0.0.1:" + port + "/ocsp");

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

                server.createContext("/ocsp", exchange -> {
                    try (exchange) {
                        byte[] requestBytes = exchange.getRequestBody().readAllBytes();
                        byte[] body = pki.ocspRespondGood(requestBytes);
                        exchange.getResponseHeaders().set("Content-Type", "application/ocsp-response");
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

        /** Certificado da TSA fake (com AIA para o responder OCSP local). */
        public X509Certificate tsaCert() {
            return tsaCert;
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

    /** Responde uma requisição OCSP (DER) com status GOOD para o serial consultado, ecoando o nonce. */
    byte[] ocspRespondGood(byte[] ocspRequestDer) {
        try {
            org.bouncycastle.cert.ocsp.OCSPReq request = new org.bouncycastle.cert.ocsp.OCSPReq(ocspRequestDer);
            X509CertificateHolder caHolder = new JcaX509CertificateHolder(caCert);

            BasicOCSPRespBuilder builder = new BasicOCSPRespBuilder(new RespID(caHolder.getSubject()));

            org.bouncycastle.asn1.x509.Extension nonce = request.getExtension(
                    org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
            if (nonce != null) {
                builder.setResponseExtensions(new org.bouncycastle.asn1.x509.Extensions(nonce));
            }

            Date now = new Date();
            Date nextUpdate = new Date(now.getTime() + 10L * 365 * 24 * 3600 * 1000);
            for (org.bouncycastle.cert.ocsp.Req req : request.getRequestList()) {
                builder.addResponse(req.getCertID(), CertificateStatus.GOOD, now, nextUpdate, null);
            }

            BasicOCSPResp basic = builder.build(
                    signer(caKeys), new X509CertificateHolder[]{caHolder}, now);
            return new OCSPRespBuilder().build(OCSPRespBuilder.SUCCESSFUL, basic).getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException("Falha ao responder requisição OCSP de teste", e);
        }
    }

    // ------------------------------------------------------------------
    // Construção de certificados
    // ------------------------------------------------------------------

    private static KeyPair rsa() throws Exception {
        return rsa(2048);
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);
        return gen.generateKeyPair();
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(256);
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
                                             X509Certificate caCert, LeafProfile profile) throws Exception {
        JcaX509v3CertificateBuilder builder = baseIssuedCert(leafKeys, caCert, profile.subjectDn());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        if (profile.policyOid() != null) {
            builder.addExtension(Extension.certificatePolicies, false,
                    new CertificatePolicies(new PolicyInformation[]{
                            new PolicyInformation(new ASN1ObjectIdentifier(profile.policyOid()))
                    }));
        }
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(profile.keyUsage()));

        if (profile.sanOid() != null) {
            // otherName ICP-Brasil (2.16.76.1.3.1: DDMMYYYY + CPF + complemento; 2.16.76.1.3.3: CNPJ)
            ASN1EncodableVector vec = new ASN1EncodableVector();
            vec.add(new ASN1ObjectIdentifier(profile.sanOid()));
            vec.add(new DERTaggedObject(true, 0, new DERUTF8String(profile.sanValue())));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(vec))));
        }

        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(leafKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        return convert(builder.build(signer(caKeys)));
    }

    private static X509Certificate buildTsa(KeyPair tsaKeys, KeyPair caKeys,
                                            X509Certificate caCert, String dn) throws Exception {
        return buildTsaWithAia(tsaKeys, caKeys, caCert, dn, null);
    }

    private static X509Certificate buildTsaWithAia(KeyPair tsaKeys, KeyPair caKeys,
                                                   X509Certificate caCert, String dn,
                                                   String ocspUrl) throws Exception {
        return buildTsaCertificate(tsaKeys, caKeys, caCert, dn, ocspUrl, true);
    }

    private static X509Certificate buildTsaCertificate(KeyPair tsaKeys, KeyPair caKeys,
                                                       X509Certificate caCert, String dn,
                                                       String ocspUrl, boolean criticalEku) throws Exception {
        JcaX509v3CertificateBuilder builder = baseIssuedCert(tsaKeys, caCert, dn);
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();

        builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        // RFC 3161 §2.3: EKU id-kp-timeStamping, marcado crítico
        builder.addExtension(Extension.extendedKeyUsage, criticalEku,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        builder.addExtension(Extension.subjectKeyIdentifier, false,
                ext.createSubjectKeyIdentifier(tsaKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false,
                ext.createAuthorityKeyIdentifier(caCert.getPublicKey()));

        if (ocspUrl != null) {
            builder.addExtension(Extension.authorityInfoAccess, false,
                    new org.bouncycastle.asn1.x509.AuthorityInformationAccess(
                            org.bouncycastle.asn1.x509.AccessDescription.id_ad_ocsp,
                            new GeneralName(GeneralName.uniformResourceIdentifier, ocspUrl)));
        }

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
