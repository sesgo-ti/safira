package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.TsaClient;
import br.gov.go.saude.fhir.safira.steps.signing.tsa.TsaUnavailableException;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
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
import org.mockito.invocation.InvocationOnMock;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class TsaTimestampStepTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private TsaClient tsaClient;
    private TsaTimestampStep step;

    @BeforeEach
    void setUp() {
        tsaClient = mock(TsaClient.class);
        step = new TsaTimestampStep(tsaClient);
    }

    @Test
    void shouldReturnSuccessWithoutChangesWhenStrategyIsIat() {
        var context = SigningContext.builder()
                .strategy(TimestampStrategy.IAT)
                .build();

        var result = step.execute(context);

        assertSuccess(result);
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        assertTrue(ctx.getAttribute(TsaTimestampStep.TSA_TOKEN_KEY, String.class).isEmpty());
    }

    @Test
    void shouldStoreTsaTokenWhenStrategyIsTsaAndResponseIsValid() throws Exception {
        long refTs = 1754006400L;
        KeyPair keys = generateKeyPair();
        X509Certificate cert = selfSign(keys, refTs - 86400, refTs + 86400);
        byte[] signatureBytes = "fake-signature-bytes".getBytes();
        String signatureB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

        when(tsaClient.requestTimestamp(anyString(), any(), anyInt()))
                .thenAnswer((InvocationOnMock invocation) -> {
                    TimeStampRequest actualRequest = invocation.getArgument(1);
                    return buildResponseFor(actualRequest, keys, cert, refTs);
                });

        var context = tsaContext(signatureB64Url, cert, refTs);
        var result = step.execute(context);

        assertSuccess(result);
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        assertTrue(ctx.getAttribute(TsaTimestampStep.TSA_TOKEN_KEY, String.class).isPresent());
    }

    @Test
    void shouldReturnTsaUnavailableWhenClientThrowsUnavailable() throws Exception {
        long refTs = 1754006400L;
        KeyPair keys = generateKeyPair();
        X509Certificate cert = selfSign(keys, refTs - 86400, refTs + 86400);
        String signatureB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString("sig".getBytes());

        when(tsaClient.requestTimestamp(anyString(), any(), anyInt()))
                .thenThrow(new TsaUnavailableException("timeout"));

        var context = tsaContext(signatureB64Url, cert, refTs);
        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.TSA_UNAVAILABLE);
    }

    @Test
    void shouldReturnFailureWhenTsaConfigMissing() {
        var context = SigningContext.builder()
                .strategy(TimestampStrategy.TSA)
                .referenceTimestamp(1754006400L)
                .attribute(CryptoSigningStep.SIGNATURE_KEY, "c2ln")
                .build();

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.CONFIG_TSA_CONFIG_MISSING);
    }

    // ===== Helpers =====

    private SigningContext tsaContext(String signatureB64Url, X509Certificate cert, long refTs) {
        var verification = new SafiraOperationalConfigProperties.VerificationProps(
                3600, 3600, 20, 20, 20, 3, 2,
                "https://tsa.example.com", null, null);
        var opConfig = new SafiraOperationalConfigProperties(verification, null, null, null, null);

        return SigningContext.builder()
                .strategy(TimestampStrategy.TSA)
                .referenceTimestamp(refTs)
                .certificateChain(new X509Certificate[]{cert})
                .attribute(CryptoSigningStep.SIGNATURE_KEY, signatureB64Url)
                .operationalConfig(opConfig)
                .build();
    }

    private KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private X509Certificate selfSign(KeyPair keys, long notBefore, long notAfter) throws Exception {
        X500Name name = new X500Name("CN=TSA Test CA");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(notBefore * 1000), new Date(notAfter * 1000),
                name, keys.getPublic());
        // TSP exige critical ExtendedKeyUsage com KeyPurposeId.id_kp_timeStamping
        builder.addExtension(Extension.extendedKeyUsage, true,
                new ExtendedKeyUsage(KeyPurposeId.id_kp_timeStamping));
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private TimeStampResponse buildResponseFor(TimeStampRequest request, KeyPair keys, X509Certificate cert, long refTs) throws Exception {
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());
        DigestCalculatorProvider digestProvider = new JcaDigestCalculatorProviderBuilder()
                .setProvider("BC").build();

        SignerInfoGenerator sig = new JcaSignerInfoGeneratorBuilder(digestProvider)
                .build(signer, cert);

        TimeStampTokenGenerator tokenGen = new TimeStampTokenGenerator(
                sig, digestProvider.get(new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_sha256)),
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.2.3.4.5"));

        X509CertificateHolder holder = new JcaX509CertificateHolder(cert);
        tokenGen.addCertificates(new org.bouncycastle.util.CollectionStore<>(java.util.List.of(holder)));

        TimeStampResponseGenerator responseGen = new TimeStampResponseGenerator(
                tokenGen, TSPAlgorithms.ALLOWED);

        return responseGen.generate(request, BigInteger.valueOf(1), new Date(refTs * 1000));
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private void assertFailure(StepResult<SigningContext> result, SignatureExceptionCode expectedCode) {
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expectedCode, ((StepResult.Failure<SigningContext>) result).code());
    }
}
