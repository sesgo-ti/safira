package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Signature;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Teste de integração que executa a pipeline completa de assinatura via {@link SigningService}.
 *
 * <p>Gera um certificado self-signed com CPF no SubjectAlternativeName, monta um Bundle e
 * Provenance simples, e verifica que a pipeline produz uma {@link Signature} FHIR válida.
 *
 * <p>O YAML de teste omite {@code chain-validation} porque certs self-signed não passam
 * na validação contra a âncora ICP-Brasil.
 */
@SpringBootTest
class SigningServiceIntegrationTest {

    private static final String TEST_CPF = "12345678901";
    private static final long REFERENCE_TIMESTAMP = Instant.now().getEpochSecond();
    private static final String POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0";

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Autowired
    private SigningService signingService;

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldSignBundleEndToEndAndReturnValidFhirSignature() throws Exception {
        KeyPair signerKeys = generateRsaKeyPair();
        X509Certificate signerCert = generateSignerCertificate(signerKeys, TEST_CPF);
        X509Certificate rootCert = generateRootCertificate();

        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "bundle-test",
                  "entry": [{
                    "fullUrl": "urn:uuid:11111111-1111-1111-1111-111111111111",
                    "resource": {
                      "resourceType": "Patient",
                      "id": "p1",
                      "name": [{"family": "Silva"}]
                    }
                  }]
                }
                """;

        String provenanceJson = """
                {
                  "resourceType": "Provenance",
                  "id": "prov-test",
                  "target": [{"reference": "urn:uuid:11111111-1111-1111-1111-111111111111"}]
                }
                """;

        SigningInput input = new SigningInput(
                mapper.readTree(bundleJson),
                mapper.readTree(provenanceJson),
                new SigningInput.PemCryptoMaterial(toPemBase64(signerKeys), null),
                List.of(toBase64(signerCert), toBase64(rootCert)),
                REFERENCE_TIMESTAMP,
                "iat",
                POLICY_URI
        );

        PipelineResult<?> result = signingService.sign(input);

        assertTrue(result.isSuccess(), "Pipeline deveria ter sucesso: " + (result.isSuccess() ? "" : result.getExceptionDetails()));
        Object value = result.getValue();
        assertInstanceOf(Signature.class, value);

        Signature signature = (Signature) value;
        assertNotNull(signature.data());
        assertTrue(signature.data().length > 0);
        assertEquals("application/jose", signature.sigFormat());
        assertEquals("application/octet-stream", signature.targetFormat());
        assertNotNull(signature.when());
        assertEquals(REFERENCE_TIMESTAMP, signature.when().getEpochSecond());

        assertNotNull(signature.who());
        assertNotNull(signature.who().identifier());
        assertEquals("urn:brasil:cpf", signature.who().identifier().system());
        assertEquals(TEST_CPF, signature.who().identifier().value());

        assertNotNull(signature.type());
        assertEquals(1, signature.type().size());
        assertEquals("1.2.840.10065.1.12.1.1", signature.type().getFirst().code());
    }

    // ===== Helpers =====

    private KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    private X509Certificate generateSignerCertificate(KeyPair keys, String cpf) throws Exception {
        X500Name name = new X500Name("CN=Test Signer");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(keys.getPrivate());

        // OID 2.16.76.1.3.1 com CPF nas posições 8-18 (conforme ICP-Brasil)
        String cpfContent = "01011990" + cpf + "00000000000" + "000000000000000";
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
        vector.add(new DERTaggedObject(true, 0, new DERUTF8String(cpfContent)));
        GeneralName cpfName = new GeneralName(GeneralName.otherName, new DERSequence(vector));
        GeneralNames san = new GeneralNames(cpfName);

        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date((REFERENCE_TIMESTAMP - 86400) * 1000),
                new Date((REFERENCE_TIMESTAMP + 86400 * 365) * 1000),
                name, keys.getPublic());
        builder.addExtension(Extension.subjectAlternativeName, false, san);

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private X509Certificate generateRootCertificate() throws Exception {
        KeyPair rootKeys = generateRsaKeyPair();
        X500Name name = new X500Name("CN=Test Root CA");
        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
                .setProvider("BC").build(rootKeys.getPrivate());

        var builder = new JcaX509v3CertificateBuilder(
                name, BigInteger.valueOf(System.nanoTime()),
                new Date((REFERENCE_TIMESTAMP - 86400) * 1000),
                new Date((REFERENCE_TIMESTAMP + 86400 * 365) * 1000),
                name, rootKeys.getPublic());

        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(builder.build(signer));
    }

    private String toPemBase64(KeyPair keys) throws Exception {
        StringWriter writer = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(writer)) {
            pemWriter.writeObject(keys.getPrivate());
        }
        return Base64.getEncoder().encodeToString(writer.toString().getBytes(StandardCharsets.UTF_8));
    }

    private String toBase64(X509Certificate cert) throws Exception {
        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }
}
