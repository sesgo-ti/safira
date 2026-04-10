package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class CryptoSigningStepTest {

    private static final long CERT_START = 1751328000L;
    private static final long CERT_END = 1893456000L;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CryptoSigningStep step;

    @BeforeEach
    void setUp() {
        step = new CryptoSigningStep();
    }

    // ===== Happy path RSA via PEM =====

    @Test
    void shouldSignWithRsaPemMaterial() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        String pemBase64 = toPemBase64(keys.getPrivate());
        var material = new CryptoMaterial.PemMaterial(pemBase64, null);
        byte[] signingInput = "header.payload".getBytes(StandardCharsets.UTF_8);
        var context = contextWith(material, signingInput);

        var result = step.execute(context);

        assertSuccess(result);
        String signatureB64 = getSignature(result);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(signatureB64);
        assertTrue(verifyRsa(keys.getPublic(), signingInput, signatureBytes));
    }

    // ===== Happy path ECDSA via PEM =====

    @Test
    void shouldSignWithEcPemMaterialAndProduce64BytesRawSignature() throws Exception {
        KeyPair keys = generateEcKeyPair();
        String pemBase64 = toPemBase64(keys.getPrivate());
        var material = new CryptoMaterial.PemMaterial(pemBase64, null);
        byte[] signingInput = "header.payload".getBytes(StandardCharsets.UTF_8);
        var context = contextWith(material, signingInput);

        var result = step.execute(context);

        assertSuccess(result);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(getSignature(result));
        assertEquals(64, signatureBytes.length);
    }

    // ===== Happy path RSA via PKCS12 =====

    @Test
    void shouldSignWithRsaPkcs12Material() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        X509Certificate cert = selfSign(keys, "CN=Test");
        String p12Base64 = buildPkcs12(keys.getPrivate(), cert, "senha", "test-alias");
        var material = new CryptoMaterial.Pkcs12Material(p12Base64, "senha", "test-alias");
        byte[] signingInput = "header.payload".getBytes(StandardCharsets.UTF_8);
        var context = contextWith(material, signingInput);

        var result = step.execute(context);

        assertSuccess(result);
        byte[] signatureBytes = Base64.getUrlDecoder().decode(getSignature(result));
        assertTrue(verifyRsa(keys.getPublic(), signingInput, signatureBytes));
    }

    // ===== PKCS12 sem alias (usa primeiro disponível) =====

    @Test
    void shouldSignWithPkcs12WithoutAliasUsingFirstAvailable() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        X509Certificate cert = selfSign(keys, "CN=Test");
        String p12Base64 = buildPkcs12(keys.getPrivate(), cert, "senha", "only-alias");
        var material = new CryptoMaterial.Pkcs12Material(p12Base64, "senha", null);
        var context = contextWith(material, "data".getBytes(StandardCharsets.UTF_8));

        var result = step.execute(context);

        assertSuccess(result);
    }

    // ===== PKCS12 alias não encontrado =====

    @Test
    void shouldReturnCertificateNotFoundWhenPkcs12AliasMissing() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        X509Certificate cert = selfSign(keys, "CN=Test");
        String p12Base64 = buildPkcs12(keys.getPrivate(), cert, "senha", "real-alias");
        var material = new CryptoMaterial.Pkcs12Material(p12Base64, "senha", "alias-inexistente");
        var context = contextWith(material, "data".getBytes(StandardCharsets.UTF_8));

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.DEVICE_CERTIFICATE_NOT_FOUND);
    }

    // ===== PKCS12 senha errada =====

    @Test
    void shouldReturnKeyInaccessibleWhenPkcs12PasswordWrong() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        X509Certificate cert = selfSign(keys, "CN=Test");
        String p12Base64 = buildPkcs12(keys.getPrivate(), cert, "senha-correta", "test-alias");
        var material = new CryptoMaterial.Pkcs12Material(p12Base64, "senha-errada", "test-alias");
        var context = contextWith(material, "data".getBytes(StandardCharsets.UTF_8));

        var result = step.execute(context);

        assertFailure(result, SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE);
    }

    // ===== Base64Url sem padding =====

    @Test
    void shouldProduceBase64UrlWithoutPadding() throws Exception {
        KeyPair keys = generateRsaKeyPair(2048);
        var material = new CryptoMaterial.PemMaterial(toPemBase64(keys.getPrivate()), null);
        var context = contextWith(material, "data".getBytes(StandardCharsets.UTF_8));

        var result = step.execute(context);

        assertSuccess(result);
        String signature = getSignature(result);
        assertFalse(signature.contains("="));
        assertFalse(signature.contains("+"));
        assertFalse(signature.contains("/"));
    }

    // ===== Falhas defensivas =====

    @Test
    void shouldThrowStepExceptionWhenSigningInputBytesMissing() {
        KeyPair keys;
        try {
            keys = generateRsaKeyPair(2048);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        CryptoMaterial.PemMaterial material;
        try {
            material = new CryptoMaterial.PemMaterial(toPemBase64(keys.getPrivate()), null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        SigningContext context = SigningContext.builder()
                .cryptoMaterial(material)
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    @Test
    void shouldThrowStepExceptionWhenCryptoMaterialMissing() {
        SigningContext context = SigningContext.builder()
                .attribute(SigningInputStep.SIGNING_INPUT_BYTES_KEY, "data".getBytes(StandardCharsets.UTF_8))
                .build();

        assertThrows(StepException.class, () -> step.execute(context));
    }

    // ===== Helpers =====

    private SigningContext contextWith(CryptoMaterial material, byte[] signingInputBytes) {
        return SigningContext.builder()
                .cryptoMaterial(material)
                .attribute(SigningInputStep.SIGNING_INPUT_BYTES_KEY, signingInputBytes)
                .build();
    }

    private KeyPair generateRsaKeyPair(int bits) throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(bits);
        return gen.generateKeyPair();
    }

    private KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(new ECGenParameterSpec("P-256"));
        return gen.generateKeyPair();
    }

    private String toPemBase64(PrivateKey key) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(key);
        }
        return Base64.getEncoder().encodeToString(writer.toString().getBytes(StandardCharsets.UTF_8));
    }

    private X509Certificate selfSign(KeyPair keys, String dn) throws Exception {
        X500Name name = new X500Name(dn);
        String sigAlg = keys.getPublic().getAlgorithm().equals("RSA")
                ? "SHA256WithRSA" : "SHA256WithECDSA";
        ContentSigner signer = new JcaContentSignerBuilder(sigAlg)
                .setProvider("BC").build(keys.getPrivate());
        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date(CERT_START * 1000), new Date(CERT_END * 1000),
                name, keys.getPublic());
        return new JcaX509CertificateConverter()
                .setProvider("BC").getCertificate(builder.build(signer));
    }

    private String buildPkcs12(PrivateKey privateKey, X509Certificate cert, String password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry(alias, privateKey, password.toCharArray(), new Certificate[]{cert});

        var baos = new java.io.ByteArrayOutputStream();
        keyStore.store(baos, password.toCharArray());
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private boolean verifyRsa(PublicKey publicKey, byte[] data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(data);
        return sig.verify(signature);
    }

    private void assertSuccess(StepResult<SigningContext> result) {
        assertInstanceOf(StepResult.Success.class, result);
    }

    private void assertFailure(StepResult<SigningContext> result, SignatureExceptionCode expectedCode) {
        assertInstanceOf(StepResult.Failure.class, result);
        assertEquals(expectedCode, ((StepResult.Failure<SigningContext>) result).code());
    }

    private String getSignature(StepResult<SigningContext> result) {
        SigningContext ctx = ((StepResult.Success<SigningContext>) result).context();
        return ctx.getAttribute(CryptoSigningStep.SIGNATURE_KEY, String.class).orElseThrow();
    }
}
