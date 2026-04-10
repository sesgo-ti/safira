package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class FhirSignatureStepTest {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private FhirSignatureStep step;

    @BeforeEach
    void setUp() {
        step = new FhirSignatureStep();
    }

    @Test
    void shouldBuildFhirSignatureWithCpfFromCertificate() throws Exception {
        String cpfContent = "01011990" + "12345678901" + "00000000000" + "000000000000000";
        X509Certificate cert = generateCertWithOtherName("2.16.76.1.3.1", cpfContent);
        String jws = "{\"payload\":\"p\",\"signatures\":[]}";
        var context = contextWith(jws, cert);

        var result = step.execute(context);

        assertSuccess(result);
        Signature signature = signature(result);
        assertEquals("application/jose", signature.sigFormat());
        assertEquals("application/octet-stream", signature.targetFormat());
        assertArrayEquals(jws.getBytes(StandardCharsets.UTF_8), signature.data());
        assertNotNull(signature.when());
        assertEquals(1754006400L, signature.when().getEpochSecond());
        assertEquals("urn:brasil:cpf", signature.who().identifier().system());
        assertEquals("12345678901", signature.who().identifier().value());
        assertEquals(1, signature.type().size());
        assertEquals("1.2.840.10065.1.12.1.1", signature.type().get(0).code());
    }

    @Test
    void shouldBuildFhirSignatureWithCnpjFromCertificate() throws Exception {
        String cnpjContent = "12345678000199";
        X509Certificate cert = generateCertWithOtherName("2.16.76.1.3.3", cnpjContent);
        String jws = "{\"payload\":\"p\",\"signatures\":[]}";
        var context = contextWith(jws, cert);

        var result = step.execute(context);

        assertSuccess(result);
        Signature signature = signature(result);
        assertEquals("urn:brasil:cnpj", signature.who().identifier().system());
        assertEquals("12345678000199", signature.who().identifier().value());
    }

    @Test
    void shouldReturnFailureWhenCertificateHasNoCpfOrCnpj() throws Exception {
        X509Certificate cert = generateCertWithoutIcpBrasilOids();
        var context = contextWith("{}", cert);

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldReturnFailureWhenCertificateHasBothCpfAndCnpj() throws Exception {
        X509Certificate cert = generateCertWithBothCpfAndCnpj(
                "01011990" + "12345678901" + "00000000000" + "000000000000000",
                "12345678000199");
        var context = contextWith("{}", cert);

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldThrowWhenJwsFinalMissing() throws Exception {
        X509Certificate cert = generateCertWithOtherName("2.16.76.1.3.3", "12345678000199");
        SigningContext context = SigningContext.builder()
                .certificateChain(new X509Certificate[]{cert})
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowWhenSignerCertificateMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(JwsFinalStep.JWS_FINAL_KEY, "{}")
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(String jwsFinal, X509Certificate cert) {
        return SigningContext.builder()
                .certificateChain(new X509Certificate[]{cert})
                .referenceTimestamp(1754006400L)
                .attribute(JwsFinalStep.JWS_FINAL_KEY, jwsFinal)
                .build();
    }

    private X509Certificate generateCertWithOtherName(String oid, String value) throws Exception {
        KeyPair keys = generateRsaKeyPair();
        X500Name name = new X500Name("CN=Test Signer");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());

        GeneralName otherName = buildOtherName(oid, value);
        GeneralNames san = new GeneralNames(otherName);

        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 86400000 * 365),
                name, keys.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, san);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private X509Certificate generateCertWithBothCpfAndCnpj(String cpfValue, String cnpjValue) throws Exception {
        KeyPair keys = generateRsaKeyPair();
        X500Name name = new X500Name("CN=Test Signer");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());

        GeneralName cpfName = buildOtherName("2.16.76.1.3.1", cpfValue);
        GeneralName cnpjName = buildOtherName("2.16.76.1.3.3", cnpjValue);
        GeneralNames san = new GeneralNames(new GeneralName[]{cpfName, cnpjName});

        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 86400000 * 365),
                name, keys.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, san);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private X509Certificate generateCertWithoutIcpBrasilOids() throws Exception {
        KeyPair keys = generateRsaKeyPair();
        X500Name name = new X500Name("CN=Test Signer");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());

        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(System.currentTimeMillis() - 86400000),
                new Date(System.currentTimeMillis() + 86400000 * 365),
                name, keys.getPublic());

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private GeneralName buildOtherName(String oid, String value) {
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1ObjectIdentifier(oid));
        vector.add(new DERTaggedObject(true, 0, new DERUTF8String(value)));
        return new GeneralName(GeneralName.otherName, new DERSequence(vector));
    }

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private void assertFailure(StepResult<SigningContext> result, SignatureExceptionCode expectedCode) {
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expectedCode, ((StepResult.Failure<SigningContext>) result).code());
    }

    private Signature signature(StepResult<SigningContext> result) {
        return ((StepResult.Success<SigningContext>) result).context().getSignature();
    }
}
