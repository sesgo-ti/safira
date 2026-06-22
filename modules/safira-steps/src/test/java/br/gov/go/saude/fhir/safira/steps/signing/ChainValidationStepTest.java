package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.steps.signing.revocation.RevocationEvidence;
import br.gov.go.saude.fhir.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation.RevocationService;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChainValidationStepTest {

    // Epoch seconds
    private static final long MIN_DATE   = 1751328000L; // 2025-07-01T00:00:00Z
    private static final long LEAF_START = 1751414400L; // 2025-07-02T00:00:00Z
    private static final long REF_TS     = 1754006400L; // 2025-08-01T00:00:00Z
    private static final long CERT_END   = 1893456000L; // 2030-01-01T00:00:00Z

    private static final X500Name ROOT_NAME  = new X500Name("CN=Test Root CA");
    private static final X500Name INTER_NAME = new X500Name("CN=Test Intermediate CA");
    private static final X500Name LEAF_NAME  = new X500Name("CN=Test Signer");

    private static final AtomicLong SERIAL = new AtomicLong(100);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Mock private TrustStoreService trustStoreService;
    @Mock private RevocationService revocationService;

    private ChainValidationStep step;

    @BeforeEach
    void setUp() {
        step = new ChainValidationStep(trustStoreService, revocationService);
    }

    // ===== 2.2 – Mínimo de 2 certificados =====

    @Test
    void shouldReturnCertChainIncompleteWhenChainIsNull() {
        var result = step.execute(context(null, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    @Test
    void shouldReturnCertChainIncompleteWhenChainHasOnlyOneCert() throws Exception {
        KeyPair rootKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        var result = step.execute(context(new X509Certificate[]{root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    // ===== 2.4 – Raiz ICP-Brasil confiável =====

    @Test
    void shouldReturnNotTrustedRootWhenLastCertIsNotSelfSigned() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END));
        // chain[1] = leaf (issuer ≠ subject) → isSelfSigned returns false
        var result = step.execute(context(new X509Certificate[]{root, leaf}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_NOT_TRUSTED_ROOT);
    }

    @Test
    void shouldReturnNotTrustedRootWhenRootIsNotInTrustStore() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(false);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_NOT_TRUSTED_ROOT);
    }

    // ===== 2.5 – Elegibilidade ICP-Brasil =====

    @Test
    void shouldReturnCertNotIcpBrasilWhenLeafLacksIcpPolicy() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END),
                false, true, true, true);
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    // ===== Key Usage =====

    @Test
    void shouldReturnCertInvalidFormatWhenLeafLacksKeyUsageExtension() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END),
                true, false, false, false);
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    @Test
    void shouldReturnCertInvalidFormatWhenLeafMissingNonRepudiationBit() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END),
                true, true, true, false);
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    // ===== 2.6 – Datas do certificado do signatário =====

    @Test
    void shouldReturnIssueDateTooOldWhenSignerCertIssuedBeforeMinimumDate() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(MIN_DATE - 86400), date(CERT_END));
        // notBefore = one day before the minimum required date (2025-06-30)
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(MIN_DATE - 86400), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD);
    }

    @Test
    void shouldReturnCertNotYetValidWhenSignerCertNotYetValidAtRefTs() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        // notBefore is one day after refTs → not yet valid
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(REF_TS + 86400), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_NOT_YET_VALID);
    }

    @Test
    void shouldReturnCertExpiredWhenSignerCertExpiredAtRefTs() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        // notAfter is one day before refTs → expired
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(REF_TS - 86400));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_EXPIRED);
    }

    // ===== 2.7 – Validação criptográfica, hierárquica e temporal da cadeia =====

    @Test
    void shouldReturnChainValidationFailedWhenCryptographicVerificationFails() throws Exception {
        KeyPair rootKp  = newKeyPair();
        KeyPair leafKp  = newKeyPair();
        KeyPair wrongKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        // leaf signed by wrongKp → leaf.verify(root.getPublicKey()) fails
        X509Certificate leaf = newLeafCert(leafKp, wrongKp, date(LEAF_START), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldReturnChainValidationFailedWhenHierarchyCheckFails() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        // leaf signed by root (crypto passes) but has a different issuer name → hierarchy fails
        X509Certificate leaf = newLeafCertWithWrongIssuer(leafKp, rootKp, date(LEAF_START), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldReturnCertExpiredWhenIntermediateCertExpiredAtRefTs() throws Exception {
        // 3-cert chain [leaf, inter, root]: leaf is valid but inter is expired
        KeyPair rootKp  = newKeyPair();
        KeyPair interKp = newKeyPair();
        KeyPair leafKp  = newKeyPair();
        X509Certificate root  = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate inter = newIntermediateCert(interKp, rootKp, date(LEAF_START), date(REF_TS - 86400));
        X509Certificate leaf  = newLeafCertByIntermediate(leafKp, interKp, date(LEAF_START), date(CERT_END));
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        var result = step.execute(context(new X509Certificate[]{leaf, inter, root}, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_EXPIRED);
    }

    // ===== 2.8 – Verificação de revogação =====

    @Test
    void shouldReturnCertRevokedWhenRevocationStatusIsRevoked() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.Revoked("OCSP"));
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldReturnRevocationNoDistributionPointsWhenCertHasNoCdpOrOcsp() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.NoDistributionPoints());
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.REVOCATION_NO_DISTRIBUTION_POINTS);
    }

    @Test
    void shouldReturnRevocationOcspUnavailableWhenOcspCheckFails() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.OcspUnavailable());
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.REVOCATION_OCSP_UNAVAILABLE);
    }

    @Test
    void shouldReturnRevocationCrlUnavailableWhenCrlCheckFails() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.CrlUnavailable());
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.REVOCATION_CRL_UNAVAILABLE);
    }

    @Test
    void shouldReturnRevocationResponseMalformedWhenResponseIsMalformed() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.Malformed("OCSP"));
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.REVOCATION_RESPONSE_MALFORMED);
    }

    @Test
    void shouldReturnRevocationNoConnectivityWhenNoNetworkAvailable() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.NoConnectivity());
        var result = step.execute(context(chain, REF_TS));
        assertFailure(result, SignatureExceptionCode.REVOCATION_NO_CONNECTIVITY);
    }

    // ===== Happy path =====

    @Test
    void shouldReturnSuccessWithOcspEvidencesWhenChainIsValid() throws Exception {
        X509Certificate[] chain = validChain();
        byte[] ocspDer = {10, 20, 30};
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.Good("OCSP", ocspDer));

        var result = step.execute(context(chain, REF_TS));

        assertTrue(result.isSuccess());
        var ctx = ((StepResult.Success<SigningContext>) result).context();

        @SuppressWarnings("unchecked")
        List<RevocationEvidence> evidences = (List<RevocationEvidence>)
                ctx.getAttributes().get(ChainValidationStep.REVOCATION_EVIDENCES_KEY);
        assertEquals(1, evidences.size());
        assertEquals("OCSP", evidences.get(0).source());
        assertEquals(Base64.getEncoder().encodeToString(ocspDer), evidences.get(0).responseDerBase64());
        assertFalse(evidences.get(0).hashSha512().isEmpty());
    }

    @Test
    void shouldReturnSuccessWithEmptyEvidencesWhenOcspResponseHasNullDer() throws Exception {
        X509Certificate[] chain = validChain();
        when(trustStoreService.isTrustedRoot(any())).thenReturn(true);
        when(revocationService.check(any(), any())).thenReturn(new RevocationStatus.Good("OCSP", null));

        var result = step.execute(context(chain, REF_TS));

        assertTrue(result.isSuccess());
        var ctx = ((StepResult.Success<SigningContext>) result).context();

        @SuppressWarnings("unchecked")
        List<RevocationEvidence> evidences = (List<RevocationEvidence>)
                ctx.getAttributes().get(ChainValidationStep.REVOCATION_EVIDENCES_KEY);
        assertTrue(evidences.isEmpty());
    }

    // ===== Certificate helpers =====

    private X509Certificate[] validChain() throws Exception {
        KeyPair rootKp = newKeyPair();
        KeyPair leafKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp, date(LEAF_START), date(CERT_END));
        X509Certificate leaf = newLeafCert(leafKp, rootKp, date(LEAF_START), date(CERT_END));
        return new X509Certificate[]{leaf, root};
    }

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate newRootCert(KeyPair kp, Date notBefore, Date notAfter) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                ROOT_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, ROOT_NAME, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static X509Certificate newLeafCert(KeyPair leafKp, KeyPair signerKp,
                                                Date notBefore, Date notAfter) throws Exception {
        return newLeafCert(leafKp, signerKp, notBefore, notAfter, true, true, true, true);
    }

    private static X509Certificate newLeafCert(KeyPair leafKp, KeyPair signerKp,
                                                Date notBefore, Date notAfter,
                                                boolean addIcpPolicy, boolean addKeyUsage,
                                                boolean digitalSig, boolean nonRepudiation) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                ROOT_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, LEAF_NAME, leafKp.getPublic());
        if (addIcpPolicy) {
            var policies = new PolicyInformation[]{
                new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.2.3.8"))
            };
            builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(policies));
        }
        if (addKeyUsage) {
            int bits = 0;
            if (digitalSig)    bits |= KeyUsage.digitalSignature;
            if (nonRepudiation) bits |= KeyUsage.nonRepudiation;
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(bits));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static X509Certificate newLeafCertWithWrongIssuer(KeyPair leafKp, KeyPair signerKp,
                                                               Date notBefore, Date notAfter) throws Exception {
        var wrongIssuer = new X500Name("CN=Wrong Issuer CA");
        var builder = new JcaX509v3CertificateBuilder(
                wrongIssuer, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, LEAF_NAME, leafKp.getPublic());
        var policies = new PolicyInformation[]{
            new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.2.3.8"))
        };
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(policies));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signerKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static X509Certificate newIntermediateCert(KeyPair intKp, KeyPair rootKp,
                                                        Date notBefore, Date notAfter) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                ROOT_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, INTER_NAME, intKp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(rootKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static X509Certificate newLeafCertByIntermediate(KeyPair leafKp, KeyPair intKp,
                                                              Date notBefore, Date notAfter) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                INTER_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                notBefore, notAfter, LEAF_NAME, leafKp.getPublic());
        var policies = new PolicyInformation[]{
            new PolicyInformation(new ASN1ObjectIdentifier("2.16.76.1.2.3.8"))
        };
        builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(policies));
        builder.addExtension(Extension.keyUsage, true,
                new KeyUsage(KeyUsage.digitalSignature | KeyUsage.nonRepudiation));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(intKp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static Date date(long epochSecond) {
        return new Date(epochSecond * 1000L);
    }

    private static SafiraOperationalConfigProperties defaultConfig() {
        var trustStore = new SafiraOperationalConfigProperties.TrustStoreProps(
                null, null, 30, 3, null, null, null, null, 1440, 2880, 10080, MIN_DATE);
        return new SafiraOperationalConfigProperties(null, trustStore, null, null, null);
    }

    private static SigningContext context(X509Certificate[] certs, long refTs) {
        return SigningContext.builder()
                .certificateChain(certs)
                .referenceTimestamp(refTs)
                .operationalConfig(defaultConfig())
                .build();
    }

    private static void assertFailure(StepResult<?> result, SignatureExceptionCode expected) {
        assertFalse(result.isSuccess());
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expected, ((StepResult.Failure<?>) result).code());
    }
}
