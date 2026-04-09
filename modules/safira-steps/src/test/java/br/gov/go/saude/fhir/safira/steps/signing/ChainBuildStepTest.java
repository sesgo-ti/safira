package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.IncompleteChainException;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ChainBuildStepTest {

    private static final long LEAF_START = 1751414400L; // 2025-07-02T00:00:00Z
    private static final long CERT_END   = 1893456000L; // 2030-01-01T00:00:00Z

    private static final X500Name ROOT_NAME = new X500Name("CN=Test Root CA");
    private static final X500Name LEAF_NAME = new X500Name("CN=Test Signer");

    private static final AtomicLong SERIAL = new AtomicLong(200);

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Mock
    private CertificateChainResolver chainResolver;

    private ChainBuildStep step;

    @BeforeEach
    void setUp() {
        step = new ChainBuildStep(chainResolver);
    }

    // ===== Cadeia nula ou vazia =====

    @Test
    void shouldReturnCertChainIncompleteWhenChainIsNull() {
        var result = step.execute(context(null));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    @Test
    void shouldReturnCertChainIncompleteWhenChainIsEmpty() {
        var result = step.execute(context(List.of()));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    // ===== Cadeia com 1 certificado: erros de formato =====

    @Test
    void shouldReturnFormatBase64InvalidWhenSingleCertHasInvalidBase64() {
        var result = step.execute(context(List.of("!!! invalido !!!")));
        assertFailure(result, SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldReturnCertInvalidFormatWhenSingleCertHasInvalidDer() {
        String garbage = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3, 4, 5});
        var result = step.execute(context(List.of(garbage)));
        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    // ===== Cadeia com 1 certificado: resolveChain retorna incompleta =====

    @Test
    void shouldReturnCertChainIncompleteWhenResolveChainThrowsIncompleteChainException() throws Exception {
        String leafB64 = toBase64(newLeafCert(newKeyPair()));
        when(chainResolver.resolveChain(any())).thenThrow(IncompleteChainException.class);
        var result = step.execute(context(List.of(leafB64)));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    @Test
    void shouldReturnCertChainIncompleteWhenResolveChainReturnsSingleCert() throws Exception {
        KeyPair rootKp = newKeyPair();
        X509Certificate leaf = newLeafCert(rootKp);
        String leafB64 = toBase64(leaf);
        when(chainResolver.resolveChain(any())).thenReturn(List.of(leaf));
        var result = step.execute(context(List.of(leafB64)));
        assertFailure(result, SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    // ===== Cadeia com 1 certificado: sucesso =====

    @Test
    void shouldReturnSuccessWithFullChainWhenResolveChainSucceeds() throws Exception {
        KeyPair rootKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp);
        X509Certificate leaf = newLeafCert(rootKp);

        String leafB64 = toBase64(leaf);
        when(chainResolver.resolveChain(any())).thenReturn(List.of(leaf, root));

        var result = step.execute(context(List.of(leafB64)));

        assertTrue(result.isSuccess());
        X509Certificate[] chain = result.context().getCertificateChain().orElseThrow();
        assertArrayEquals(new X509Certificate[]{leaf, root}, chain);
        verify(chainResolver).resolveChain(leaf);
    }

    // ===== Cadeia com 2+ certificados: erros de formato =====

    @Test
    void shouldReturnFormatBase64InvalidWhenFirstOfMultipleCertsHasInvalidBase64() throws Exception {
        String validB64 = toBase64(newRootCert(newKeyPair()));
        var result = step.execute(context(List.of("!!! invalido !!!", validB64)));
        assertFailure(result, SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldReturnCertInvalidFormatWhenSecondOfMultipleCertsHasInvalidDer() throws Exception {
        String validB64   = toBase64(newLeafCert(newKeyPair()));
        String garbageB64 = Base64.getEncoder().encodeToString(new byte[]{1, 2, 3});
        var result = step.execute(context(List.of(validB64, garbageB64)));
        assertFailure(result, SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    // ===== Cadeia com 2+ certificados: sucesso =====

    @Test
    void shouldReturnSuccessWithChainWhenMultipleCertsAreValid() throws Exception {
        KeyPair rootKp = newKeyPair();
        X509Certificate root = newRootCert(rootKp);
        X509Certificate leaf = newLeafCert(rootKp);

        var result = step.execute(context(List.of(toBase64(leaf), toBase64(root))));

        assertTrue(result.isSuccess());
        X509Certificate[] chain = result.context().getCertificateChain().orElseThrow();
        assertArrayEquals(new X509Certificate[]{leaf, root}, chain);
        verify(chainResolver, never()).resolveChain(any());
    }

    // ===== Certificate helpers =====

    private static KeyPair newKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        return kpg.generateKeyPair();
    }

    private static X509Certificate newRootCert(KeyPair kp) throws Exception {
        var builder = new JcaX509v3CertificateBuilder(
                ROOT_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                date(LEAF_START), date(CERT_END), ROOT_NAME, kp.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(kp.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).getCertificate(builder.build(signer));
    }

    private static X509Certificate newLeafCert(KeyPair signerKp) throws Exception {
        KeyPair leafKp = newKeyPair();
        var builder = new JcaX509v3CertificateBuilder(
                ROOT_NAME, BigInteger.valueOf(SERIAL.getAndIncrement()),
                date(LEAF_START), date(CERT_END), LEAF_NAME, leafKp.getPublic());
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

    private static String toBase64(X509Certificate cert) throws Exception {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    private static Date date(long epochSecond) {
        return new Date(epochSecond * 1000L);
    }

    private static SigningContext context(List<String> rawChain) {
        return SigningContext.builder()
                .rawCertificateChain(rawChain)
                .build();
    }

    private static void assertFailure(StepResult<?> result, SignatureExceptionCode expected) {
        assertFalse(result.isSuccess());
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expected, ((StepResult.Failure<?>) result).code());
    }
}
