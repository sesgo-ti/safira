/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.rest.request.SigningRequestParser;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS12PfxPdu;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Ataques de QA ao {@code POST /assinar} (política 0.2.0). Cada teste afirma o comportamento
 * SEGURO; os que falham documentam uma vulnerabilidade e ficam {@code @Disabled("VULN-An")}.
 */
@SpringBootTest
@Import(OfflineRevocationConfig.class)
class QaAssinaturaAtaquesTest {

    static final TestPki PKI = TestPki.create();
    static final String POLICY_OID = "2.16.76.1.2.3.1";
    static final String CPF = TestPki.TEST_CPF;
    static final String PASSWORD = "S3nh@-Secreta-QA-123";
    private static final BouncyCastleProvider BC = new BouncyCastleProvider();
    private static final SecureRandom RANDOM = new SecureRandom();

    @MockitoBean
    TrustMaterialSource trustMaterialSource;

    @Autowired
    WebApplicationContext webApplicationContext;

    @Autowired
    SafiraOperationalConfigProperties operationalConfig;

    private MockMvc mockMvc;
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        registry.add("safira.policy.accepted-certificate-policies[0].oid", () -> POLICY_OID);
        registry.add("safira.policy.accepted-certificate-policies[0].type", () -> "A3");
        registry.add("safira.policy.accepted-certificate-policies[0].issuer-sha256", PKI::issuerSha256);
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        when(trustMaterialSource.current()).thenReturn(Optional.of(TrustMaterial.of(List.of(PKI.caCert))));
        OfflineRevocationConfig.responder = PKI::ocspGoodFor;
    }

    // ------------------------------------------------------------------ chave × certificado

    @Test
    void shouldRejectSigningWhenPemPrivateKeyDoesNotMatchCertificate() throws Exception {
        KeyPair other = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(other.getPrivate()));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CRYPTO.");
    }

    @Test
    void shouldRejectSigningWhenPkcs12KeyDoesNotMatchCertificate() throws Exception {
        KeyPair other = rsa(2048);
        X509Certificate otherCert = leaf(other, LeafSpec.a3());
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", p12Material(p12(Map.of("outro", new Entry(other.getPrivate(), otherCert))), "outro"));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CRYPTO.");
    }

    @Test
    void shouldRejectSigningWhenPkcs12WithoutAliasHasOnlyForeignKeys() throws Exception {
        KeyPair other = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", p12Material(
                p12(Map.of("intruso", new Entry(other.getPrivate(), leaf(other, LeafSpec.a3())))), null));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenPkcs12AliasIsMissing() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", p12Material(
                p12(Map.of("titular", new Entry(PKI.leafKeys.getPrivate(), PKI.leafCert))), "inexistente"));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("DEVICE.CERTIFICATE-NOT-FOUND");
    }

    @Test
    void shouldRejectSigningWhenPkcs12AliasIsOversized() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", p12Material(
                p12(Map.of("titular", new Entry(PKI.leafKeys.getPrivate(), PKI.leafCert))), "a".repeat(65)));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("MIDDLEWARE.TOKEN-LABEL-INVALID");
    }

    // ------------------------------------------------------------------ cadeia / certificado

    @Test
    void shouldRejectSigningWhenLeafIsSelfSignedWithIcpOids() throws Exception {
        KeyPair keys = rsa(2048);
        X509Certificate selfSigned = issue(keys, keys, new X500Name("CN=Fulano de Tal:" + CPF + ",SERIALNUMBER=" + CPF),
                new X500Name("CN=Fulano de Tal:" + CPF + ",SERIALNUMBER=" + CPF), LeafSpec.a3());
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(selfSigned));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CERT.");
    }

    @Test
    void shouldRejectSigningWhenChainCarriesRogueCaWithTrustedCaName() throws Exception {
        KeyPair rogueCaKeys = rsa(2048);
        X500Name caName = X500Name.getInstance(PKI.caCert.getSubjectX500Principal().getEncoded());
        X509Certificate rogueCa = issue(rogueCaKeys, rogueCaKeys, caName, caName,
                LeafSpec.authority());
        KeyPair keys = rsa(2048);
        X509Certificate rogueLeaf = issue(keys, rogueCaKeys, caName, LeafSpec.a3().subject(), LeafSpec.a3());
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(rogueLeaf, rogueCa));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CERT.");
    }

    @Test
    void shouldRejectSigningWhenSignerIsTheTrustedCa() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(PKI.caKeys.getPrivate()));
        body.put("certificateChain", chain(PKI.caCert));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CERT.");
    }

    @Test
    void shouldRejectSigningWhenSubordinateCaCarriesIcpPolicyAndCpf() throws Exception {
        KeyPair keys = rsa(2048);
        X509Certificate subCa = leaf(keys, LeafSpec.a3().withCa(true).withKeyUsage(
                KeyUsage.digitalSignature | KeyUsage.keyCertSign));
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(subCa));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CERT.");
    }

    @Test
    void shouldRejectSigningWhenChainOrderPutsCaFirst() throws Exception {
        Map<String, String> body = baseBody();
        body.put("certificateChain", chain(PKI.caCert, PKI.leafCert));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @ParameterizedTest
    @ValueSource(strings = {"2.16.76.1.2.1.1", "2.5.29.32.0", "2.16.76.1.2.3.2", "2.16.76.1.2.3", "1.2.3.4.5.6.7"})
    void shouldRejectSigningWhenLeafPolicyIsNotAllowlisted(String oid) throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withPolicies(List.of(oid)))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CERT.NOT-ICP-BRASIL");
    }

    @Test
    void shouldRejectSigningWhenLeafDeclaresTwoIcpPolicies() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withPolicies(List.of(POLICY_OID, "2.16.76.1.2.4.1")))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenLeafKeyIsEc() throws Exception {
        KeyPair keys = ec();
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3())));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CERT.UNSUPPORTED-ALGORITHM");
    }

    @ParameterizedTest
    @ValueSource(ints = {1024, 3072})
    void shouldRejectSigningWhenLeafRsaSizeIsNotAllowed(int bits) throws Exception {
        KeyPair keys = rsa(bits);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3())));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CERT.WEAK-KEY");
    }

    @Test
    void shouldRejectSigningWhenLeafLacksDigitalSignatureKeyUsage() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withKeyUsage(KeyUsage.keyEncipherment))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenSerialNumberCpfDiffersFromSanCpf() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withSanCpf("11144477735"))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CERT.MISSING-IDENTIFICATION");
    }

    @Test
    void shouldRejectSigningWhenLeafIsNotYetValid() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withValidity(
                Instant.now().plus(Duration.ofDays(1)), Instant.now().plus(Duration.ofDays(400))))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenLeafWasIssuedBeforeMinimumDate() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withValidity(
                Instant.parse("2025-06-01T00:00:00Z"), Instant.now().plus(Duration.ofDays(400))))));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenLeafHasUnknownCriticalExtension() throws Exception {
        KeyPair keys = rsa(2048);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(keys.getPrivate()));
        body.put("certificateChain", chain(leaf(keys, LeafSpec.a3().withUnknownCriticalExtension())));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenProvenanceAgentIsSomeoneElse() throws Exception {
        Map<String, String> body = baseBody();
        body.put("provenance", JadesSigningSystemTest.example("provenance.json").replace(CPF, "11144477735"));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("VALIDATION.POLICY-COMPLIANCE-FAILED");
    }

    @Test
    void shouldRejectSigningWhenLeafIsRevoked() throws Exception {
        OfflineRevocationConfig.responder = PKI::ocspRevokedFor;

        MvcResult result = sign(baseBody());

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CERT.REVOKED");
    }

    @Test
    void shouldRejectSigningWhenRevocationIsUnavailable() throws Exception {
        OfflineRevocationConfig.responder = certificate -> null;

        MvcResult result = sign(baseBody());

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    // ------------------------------------------------------------------ parâmetros de contexto

    @ParameterizedTest
    @ValueSource(strings = {"\"TSA\"", "\"IAT\"", "\"iat \"", "\" tsa\"", "\"\"", "1", "null", "[\"iat\"]", "\"iat\\u0000\""})
    void shouldRejectSigningWhenStrategyIsNotExact(String strategy) throws Exception {
        Map<String, String> body = baseBody();
        body.put("strategy", strategy);

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CONFIG.INVALID-STRATEGY");
    }

    @Test
    void shouldRejectTsaStrategyWithoutTsaPoliciesBeforeAnyNetworkCall() throws Exception {
        Map<String, String> body = baseBody();
        body.put("strategy", "\"tsa\"");
        body.put("tsaUrl", "\"http://169.254.169.254/latest/meta-data\"");

        long start = System.nanoTime();
        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("CONFIG.");
        assertThat(Duration.ofNanos(System.nanoTime() - start)).isLessThan(Duration.ofSeconds(5));
    }

    @Test
    void shouldIgnoreClientSuppliedTsaUrlAndOperationalOverrides() {
        String body = "{\"bundle\":{},\"provenance\":{},\"signerCryptoMaterial\":{\"type\":\"PEM\",\"privateKeyBase64\":\"x\"},"
                + "\"strategy\":\"tsa\",\"tsaUrl\":\"http://127.0.0.1:8080/\","
                + "\"operational\":{\"verification\":{\"tsaUrl\":\"http://127.0.0.1/\"}},"
                + "\"operationalConfig\":{\"verification\":{\"tsa-url\":\"http://127.0.0.1/\"}}}";

        SigningContext context = SigningRequestParser.parse(body, operationalConfig);

        assertThat(context.getOperationalConfig()).isSameAs(operationalConfig);
        assertThat(context.getOperationalConfig().verification().tsaUrl()).isEqualTo("https://tsa.example.com");
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://FHIR.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0/",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0?x=1",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0#frag",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0|0.2.0",
            "http://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.00",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.1",
            "https://fhir.saude.go.gov.br:443/r4/seguranca/assinatura/politica/0.2.0",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/../politica/0.2.0",
            "https://fhir.saude.gо.gov.br/r4/seguranca/assinatura/politica/0.2.0",
            "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0 ",
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.2.0"})
    void shouldRejectSigningWhenPolicyUriIsAVariant(String uri) throws Exception {
        Map<String, String> body = baseBody();
        body.put("policyIdentifierUri", mapper.writeValueAsString(uri));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).startsWith("POLICY.");
    }

    @ParameterizedTest
    @ValueSource(strings = {"-1", "0", "1751327999", "4102444801", "9223372036854775808", "-9223372036854775809",
            "1.5", "1e9", "\"1760000000\"", "null", "true", "PLUS_301", "MINUS_301"})
    void shouldRejectSigningWhenReferenceTimestampIsOutOfBoundsOrMalformed(String raw) throws Exception {
        long now = Instant.now().getEpochSecond();
        String value = switch (raw) {
            case "PLUS_301" -> Long.toString(now + 301);
            case "MINUS_301" -> Long.toString(now - 301);
            default -> raw;
        };
        Map<String, String> body = baseBody();
        body.put("referenceTimestamp", value);

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).contains("TIMESTAMP");
    }

    @ParameterizedTest
    @ValueSource(strings = {"pkcs12", "PEM ", "SMARTCARD", "TOKEN", "REMOTE", ""})
    void shouldRejectSigningWhenCryptoMaterialTypeIsUnsupported(String type) throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", "{\"type\":" + mapper.writeValueAsString(type)
                + ",\"privateKeyBase64\":\"" + pemBase64(PKI.leafKeys.getPrivate(), null) + "\",\"remoteUrl\":\"http://127.0.0.1/\"}");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("CONFIG.INVALID-PARAMETER");
    }

    // ------------------------------------------------------------------ formato / Base64

    @ParameterizedTest
    @ValueSource(strings = {"!!!", "QUJD\nREVG", "-_-_", "QUJD====", " "})
    void shouldRejectSigningWhenCertificateBase64IsMalformed(String raw) throws Exception {
        Map<String, String> body = baseBody();
        body.put("certificateChain", "[" + mapper.writeValueAsString(raw) + "]");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isIn("FORMAT.BASE64-INVALID", "CERT.INVALID-FORMAT");
    }

    @Test
    void shouldRejectSigningWhenCertificateChainIsEmptyOrHasNonStrings() throws Exception {
        Map<String, String> empty = baseBody();
        empty.put("certificateChain", "[]");
        Map<String, String> numbers = baseBody();
        numbers.put("certificateChain", "[1,{}]");

        MvcResult emptyResult = sign(empty);
        MvcResult numbersResult = sign(numbers);

        assertThat(emptyResult.getResponse().getStatus()).isEqualTo(422);
        assertThat(numbersResult.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenPkcs12ContentIsNotBase64() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", "{\"type\":\"PKCS12\",\"contentBase64\":\"%%%\",\"password\":\"x\",\"alias\":\"a\"}");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BASE64-INVALID");
    }

    @Test
    void shouldRejectSigningWhenRequestHasDuplicateMembers() throws Exception {
        Map<String, String> body = baseBody();
        String json = toJson(body).replaceFirst("\\{", "{\"strategy\":\"tsa\",");

        MvcResult result = sign(json);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }

    @Test
    void shouldRejectSigningWhenBundleResourceHasDuplicateMembers() throws Exception {
        Map<String, String> body = baseBody();
        body.put("bundle", JadesSigningSystemTest.example("bundle.json")
                .replace("\"status\": \"final\",", "\"status\": \"final\", \"status\": \"cancelled\","));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectSigningWhenJsonIsDeeplyNested() throws Exception {
        Map<String, String> body = baseBody();
        body.put("padding", "[".repeat(100_000) + "]".repeat(100_000));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }

    // ------------------------------------------------------------------ vazamento de segredos

    @Test
    void shouldNotLeakPasswordWhenPkcs12PasswordIsWrong() throws Exception {
        Map<String, String> body = baseBody();
        byte[] p12 = p12(Map.of("titular", new Entry(PKI.leafKeys.getPrivate(), PKI.leafCert)));
        body.put("signerCryptoMaterial", "{\"type\":\"PKCS12\",\"contentBase64\":\"" + Base64.getEncoder().encodeToString(p12)
                + "\",\"password\":\"senha-errada-QA-999\",\"alias\":\"titular\"}");

        MvcResult result = sign(body);

        String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(response).doesNotContain("senha-errada-QA-999").doesNotContain(PASSWORD)
                .doesNotContain("Exception").doesNotContain("\tat ");
    }

    @Test
    void shouldNotLeakPasswordOrKeyWhenEncryptedPemPasswordIsWrong() throws Exception {
        String encrypted = pemBase64(PKI.leafKeys.getPrivate(), PASSWORD);
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", "{\"type\":\"PEM\",\"privateKeyBase64\":\"" + encrypted
                + "\",\"password\":\"senha-errada-QA-999\"}");

        MvcResult result = sign(body);

        String response = result.getResponse().getContentAsString(StandardCharsets.UTF_8);
        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(response).doesNotContain("senha-errada-QA-999").doesNotContain(PASSWORD)
                .doesNotContain(encrypted.substring(0, 40));
    }

    @Test
    void shouldSignWhenEncryptedPemPasswordIsCorrect() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", "{\"type\":\"PEM\",\"privateKeyBase64\":\""
                + pemBase64(PKI.leafKeys.getPrivate(), PASSWORD) + "\",\"password\":\"" + PASSWORD + "\"}");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
    }

    @Test
    void shouldNotExposeInternalExceptionMessagesWhenPemMaterialIsIncomplete() throws Exception {
        Map<String, String> missing = baseBody();
        missing.put("signerCryptoMaterial", "{\"type\":\"PEM\"}");
        Map<String, String> garbage = baseBody();
        garbage.put("signerCryptoMaterial", "{\"type\":\"PEM\",\"privateKeyBase64\":\""
                + Base64.getEncoder().encodeToString("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"
                .getBytes(StandardCharsets.US_ASCII)) + "\"}");

        String missingResponse = sign(missing).getResponse().getContentAsString(StandardCharsets.UTF_8);
        String garbageResponse = sign(garbage).getResponse().getContentAsString(StandardCharsets.UTF_8);

        assertThat(missingResponse).doesNotContain("Cannot invoke").doesNotContain("java.").doesNotContain("\"null\"");
        assertThat(garbageResponse).doesNotContain("Exception").doesNotContain("org.bouncycastle").doesNotContain("java.");
    }

    @Test
    void shouldNotExposeSecretsWhenSigningContextIsLogged() {
        String key = pemBase64(PKI.leafKeys.getPrivate(), null);
        SigningContext context = SigningContext.builder()
                .cryptoMaterial(new CryptoMaterial.Pkcs12Material("conteudo-p12", PASSWORD, "titular"))
                .build();
        CryptoMaterial pem = new CryptoMaterial.PemMaterial(key, PASSWORD);

        assertThat(context.toString()).doesNotContain(PASSWORD).doesNotContain("conteudo-p12");
        assertThat(pem.toString()).doesNotContain(PASSWORD).doesNotContain(key.substring(0, 40));
    }

    // ------------------------------------------------------------------ DoS

    @Test
    void shouldRejectSigningWhenRequestBodyExceedsSecurityLimit() throws Exception {
        String chunk = "\"" + "A".repeat(10_000_000) + "\"";
        Map<String, String> body = baseBody();
        body.put("padding", "[" + String.join(",", List.of(chunk, chunk, chunk, chunk, chunk, chunk)) + "]");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isIn(413, 422);
    }

    @Test
    void shouldRejectValidationWhenRequestBodyExceedsSecurityLimit() throws Exception {
        String padding = "A".repeat(60_000_000);

        MvcResult result = validate("{\"data\":\"eA==\",\"padding\":\"" + padding + "\"}",
                JadesSigningSystemTest.example("bundle.json"), JadesSigningSystemTest.example("provenance.json"));

        assertThat(result.getResponse().getStatus()).isEqualTo(413);
        assertThat(code(result)).isEqualTo("SECURITY.BUNDLE-SIZE-LIMIT-EXCEEDED");
    }

    @Test
    void shouldRejectSigningWhenCertificateChainIsAbsurdlyLong() throws Exception {
        KeyPair junkKeys = rsa(2048);
        List<X509Certificate> certificates = new ArrayList<>(List.of(PKI.leafCert));
        for (int i = 0; i < 2000; i++) {
            X500Name name = new X500Name("CN=Lixo " + i);
            certificates.add(issue(junkKeys, junkKeys, name, name, LeafSpec.authority()));
        }
        Map<String, String> body = baseBody();
        body.put("certificateChain", chain(certificates.toArray(X509Certificate[]::new)));

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldBoundPkcs12KeyDerivationCostWhenIterationCountIsAbusive() throws Exception {
        byte[] p12;
        System.setProperty("keystore.pkcs12.macIterationCount", "5000000");
        System.setProperty("keystore.pkcs12.keyPbeIterationCount", "5000000");
        try {
            p12 = p12(Map.of("titular", new Entry(PKI.leafKeys.getPrivate(), PKI.leafCert)));
        } finally {
            System.clearProperty("keystore.pkcs12.macIterationCount");
            System.clearProperty("keystore.pkcs12.keyPbeIterationCount");
        }
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", "{\"type\":\"PKCS12\",\"contentBase64\":\"" + Base64.getEncoder().encodeToString(p12)
                + "\",\"password\":\"senha-errada\",\"alias\":\"titular\"}");

        long start = System.nanoTime();
        MvcResult result = sign(body);
        Duration elapsed = Duration.ofNanos(System.nanoTime() - start);

        assertThat(new PKCS12PfxPdu(p12).toASN1Structure().getMacData().getIterationCount()).isEqualTo(BigInteger.valueOf(5_000_000));
        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(elapsed).isLessThan(Duration.ofSeconds(3));
    }

    // ------------------------------------------------------------------ diferencial assinar × validar

    @Test
    void shouldSignAndValidateWhenRequestIsLegitimate() throws Exception {
        MvcResult signed = sign(baseBody());
        assertThat(signed.getResponse().getStatus()).isEqualTo(200);
        JsonNode response = json(signed);

        MvcResult validated = validate(response.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                response.get("provenance").toString());

        assertThat(validated.getResponse().getStatus()).isEqualTo(200);
        assertThat(code(validated)).isEqualTo("VALIDATION.SUCCESS");
    }

    @ParameterizedTest
    @ValueSource(strings = {"13.5", "1.350e1", "13.500", "135E-1"})
    void shouldRejectValidationWhenSignedDecimalIsRewrittenLexically(String rewritten) throws Exception {
        MvcResult signed = sign(baseBody());
        JsonNode response = json(signed);
        String tampered = JadesSigningSystemTest.example("bundle.json").replace("\"value\": 13.50", "\"value\": " + rewritten);

        MvcResult validated = validate(response.get("signature").toString(), tampered, response.get("provenance").toString());

        assertThat(validated.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectValidationWhenSignedProvenanceAgentIsSwapped() throws Exception {
        MvcResult signed = sign(baseBody());
        JsonNode response = json(signed);
        String provenance = response.get("provenance").toString().replace("\"value\":\"" + CPF + "\"", "\"value\":\"11144477735\"");

        MvcResult validated = validate(response.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"), provenance);

        assertThat(validated.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldNeverEmitSignatureThatFailsValidationWhenKeyIsSwapped() throws Exception {
        Map<String, String> body = baseBody();
        body.put("signerCryptoMaterial", pemMaterial(rsa(2048).getPrivate()));

        MvcResult signed = sign(body);
        String validationCode = signed.getResponse().getStatus() != 200 ? "NOT-EMITTED" : code(validate(
                json(signed).get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                json(signed).get("provenance").toString()));

        assertThat(validationCode).isIn("NOT-EMITTED", "VALIDATION.SUCCESS");
    }

    // ================================================================== infraestrutura

    private MvcResult sign(Map<String, String> body) throws Exception {
        return sign(toJson(body));
    }

    private MvcResult sign(String json) throws Exception {
        return mockMvc.perform(post("/assinar").contentType(MediaType.APPLICATION_JSON).content(json)).andReturn();
    }

    private MvcResult validate(String signature, String bundle, String provenance) throws Exception {
        return mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON)
                .content(SignAndValidateSystemTest.validationBody(signature, bundle, provenance))).andReturn();
    }

    private JsonNode json(MvcResult result) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private String code(MvcResult result) throws Exception {
        return json(result).get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    private static String toJson(Map<String, String> body) {
        return body.entrySet().stream()
                .map(e -> "\"" + e.getKey() + "\":" + e.getValue())
                .collect(Collectors.joining(",", "{", "}"));
    }

    private static Map<String, String> baseBody() throws Exception {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("bundle", JadesSigningSystemTest.example("bundle.json"));
        body.put("provenance", JadesSigningSystemTest.example("provenance.json"));
        body.put("signerCryptoMaterial", pemMaterial(PKI.leafKeys.getPrivate()));
        body.put("certificateChain", chain(PKI.leafCert));
        body.put("referenceTimestamp", Long.toString(Instant.now().getEpochSecond()));
        body.put("strategy", "\"iat\"");
        body.put("policyIdentifierUri", "\"" + JadesSigningSystemTest.POLICY_URI + "\"");
        return body;
    }

    private static String chain(X509Certificate... certificates) throws Exception {
        List<String> encoded = new ArrayList<>();
        for (X509Certificate certificate : certificates) {
            encoded.add("\"" + Base64.getEncoder().encodeToString(certificate.getEncoded()) + "\"");
        }
        return "[" + String.join(",", encoded) + "]";
    }

    private static String pemMaterial(PrivateKey key) {
        return "{\"type\":\"PEM\",\"privateKeyBase64\":\"" + pemBase64(key, null) + "\"}";
    }

    private static String p12Material(byte[] p12, String alias) {
        return "{\"type\":\"PKCS12\",\"contentBase64\":\"" + Base64.getEncoder().encodeToString(p12)
                + "\",\"password\":\"" + PASSWORD + "\"" + (alias == null ? "" : ",\"alias\":\"" + alias + "\"") + "}";
    }

    private static String pemBase64(PrivateKey key, String password) {
        try {
            StringWriter writer = new StringWriter();
            try (JcaPEMWriter pem = new JcaPEMWriter(writer)) {
                if (password == null) {
                    pem.writeObject(key);
                } else {
                    pem.writeObject(key, new JcePEMEncryptorBuilder("AES-256-CBC").setProvider(BC)
                            .build(password.toCharArray()));
                }
            }
            return Base64.getEncoder().encodeToString(writer.toString().getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private record Entry(PrivateKey key, X509Certificate certificate) {
    }

    private static byte[] p12(Map<String, Entry> entries) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        for (Map.Entry<String, Entry> entry : entries.entrySet()) {
            keyStore.setKeyEntry(entry.getKey(), entry.getValue().key(), PASSWORD.toCharArray(),
                    new Certificate[]{entry.getValue().certificate(), PKI.caCert});
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        keyStore.store(out, PASSWORD.toCharArray());
        return out.toByteArray();
    }

    private static KeyPair rsa(int bits) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(bits, RANDOM);
        return generator.generateKeyPair();
    }

    private static KeyPair ec() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(256, RANDOM);
        return generator.generateKeyPair();
    }

    /** Perfil do certificado emitido pela CA de teste (ou autoassinado). */
    private record LeafSpec(List<String> policies, int keyUsage, boolean ca, String sanCpf, Instant notBefore,
                            Instant notAfter, boolean unknownCritical) {

        static LeafSpec a3() {
            return new LeafSpec(List.of(POLICY_OID), KeyUsage.digitalSignature | KeyUsage.nonRepudiation, false, CPF,
                    Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(365)), false);
        }

        static LeafSpec authority() {
            return new LeafSpec(List.of(), KeyUsage.keyCertSign | KeyUsage.cRLSign, true, null,
                    Instant.now().minus(Duration.ofHours(1)), Instant.now().plus(Duration.ofDays(365)), false);
        }

        X500Name subject() {
            return new X500Name("CN=Fulano de Tal:" + CPF + ",SERIALNUMBER=" + CPF);
        }

        LeafSpec withPolicies(List<String> value) {
            return new LeafSpec(value, keyUsage, ca, sanCpf, notBefore, notAfter, unknownCritical);
        }

        LeafSpec withKeyUsage(int value) {
            return new LeafSpec(policies, value, ca, sanCpf, notBefore, notAfter, unknownCritical);
        }

        LeafSpec withCa(boolean value) {
            return new LeafSpec(policies, keyUsage, value, sanCpf, notBefore, notAfter, unknownCritical);
        }

        LeafSpec withSanCpf(String value) {
            return new LeafSpec(policies, keyUsage, ca, value, notBefore, notAfter, unknownCritical);
        }

        LeafSpec withValidity(Instant from, Instant to) {
            return new LeafSpec(policies, keyUsage, ca, sanCpf, from, to, unknownCritical);
        }

        LeafSpec withUnknownCriticalExtension() {
            return new LeafSpec(policies, keyUsage, ca, sanCpf, notBefore, notAfter, true);
        }
    }

    private static X509Certificate leaf(KeyPair keys, LeafSpec spec) throws Exception {
        return issue(keys, PKI.caKeys, X500Name.getInstance(PKI.caCert.getSubjectX500Principal().getEncoded()),
                spec.subject(), spec);
    }

    private static X509Certificate issue(KeyPair subjectKeys, KeyPair issuerKeys, X500Name issuer, X500Name subject,
                                         LeafSpec spec) throws Exception {
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, new BigInteger(127, RANDOM).add(BigInteger.ONE),
                Date.from(spec.notBefore()), Date.from(spec.notAfter()), subject, subjectKeys.getPublic());
        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        if (!spec.policies().isEmpty()) {
            builder.addExtension(Extension.certificatePolicies, false, new CertificatePolicies(spec.policies().stream()
                    .map(oid -> new PolicyInformation(new ASN1ObjectIdentifier(oid)))
                    .toArray(PolicyInformation[]::new)));
        }
        builder.addExtension(Extension.keyUsage, true, new KeyUsage(spec.keyUsage()));
        if (spec.ca()) {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        }
        if (spec.sanCpf() != null) {
            ASN1EncodableVector otherName = new ASN1EncodableVector();
            otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
            otherName.add(new DERTaggedObject(true, 0, new DERUTF8String("01011990" + spec.sanCpf() + "0".repeat(18))));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(otherName))));
        }
        if (spec.unknownCritical()) {
            builder.addExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"), true, new DEROctetString(new byte[]{1}));
        }
        builder.addExtension(Extension.subjectKeyIdentifier, false, ext.createSubjectKeyIdentifier(subjectKeys.getPublic()));
        builder.addExtension(Extension.authorityKeyIdentifier, false, ext.createAuthorityKeyIdentifier(issuerKeys.getPublic()));
        return new JcaX509CertificateConverter().getCertificate(builder.build(
                new JcaContentSignerBuilder("SHA256withRSA").setProvider(BC).build(issuerKeys.getPrivate())));
    }
}
