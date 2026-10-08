/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJsonException;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.TokenOptions;
import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest;
import br.gov.go.saude.fhir.safira.steps.content.SignedContentRules;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.IcpBrasilCertificateVerifiers;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
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
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * QA adversarial da validação (política 0.2.0): artefatos legítimos produzidos com a PKI de teste
 * e depois adulterados — com ou sem nova assinatura pela chave do titular — percorrem o pipeline
 * de validação completo, na ordem de {@code application.yml}. Cada teste afirma o comportamento
 * seguro; os desativados com {@code VULN-Vn} documentam vulnerabilidades encontradas.
 */
class QaValidacaoAtaquesTest {

    private static final Base64.Encoder URL = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Encoder STD = Base64.getEncoder();
    private static final String SUCCESS = SignatureExceptionCode.VALIDATION_SUCCESS.getCode();
    private static final String INTERNAL_ERROR = "INTERNAL_ERROR";
    private static final String OTHER_CPF = "11144477735";
    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static SafiraPolicyProperties policy;
    private static TrustMaterialSource trust;

    /** Artefato submetido à validação: entradas 1, 2, 3 e 4. */
    private record Artifact(JsonObject signature, JsonObject bundle, JsonObject provenance, long reference) {

        Artifact withSignature(UnaryOperator<JsonObject> change) {
            JsonObject changed = change.apply(signature);
            return new Artifact(changed, bundle, provenance.with("signature", new JsonArray(List.of(changed))), reference);
        }

        Artifact withBundle(String json) {
            return new Artifact(signature, LosslessJson.parseObject(json), provenance, reference);
        }

        Artifact withProvenance(UnaryOperator<JsonObject> change) {
            return new Artifact(signature, bundle, change.apply(provenance), reference);
        }

        Artifact withReference(long value) {
            return new Artifact(signature, bundle, provenance, value);
        }
    }

    /** Partes de um JWS compacto: textos Base64URL do protected header, do payload e da assinatura. */
    private record Jws(String protectedB64, String payload, String signature) {

        String json(String unprotectedHeader) {
            return "{\"payload\":\"" + payload + "\",\"signatures\":[{\"protected\":\"" + protectedB64 + "\""
                    + (unprotectedHeader == null ? "" : ",\"header\":" + unprotectedHeader)
                    + ",\"signature\":\"" + signature + "\"}]}";
        }

        String json() {
            return json(null);
        }
    }

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
        trust = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert)));
    }

    @AfterAll
    static void stop() {
        tsa.close();
    }

    // ---------------------------------------------------------------------------------------------
    // Infraestrutura: pipeline completo de validação e forja de artefatos
    // ---------------------------------------------------------------------------------------------

    private static String validate(Artifact artifact) {
        return validate(artifact, policy, trust, pki.ocspGoodSource());
    }

    /** Executa os steps na ordem do pipeline VALIDATION 0.2.0; exceção vira INTERNAL_ERROR (PipelineExecutor). */
    private static String validate(Artifact artifact, SafiraPolicyProperties policy, TrustMaterialSource trust,
                                   RevocationSource<OCSP> ocsp) {
        List<ValidationStep> steps = List.of(
                new ValidationRequestContextStep(policy, trust, Clock.systemUTC()),
                new SignatureBindingStep(),
                new JwsStructureStep(),
                new ContentIntegrityStep(),
                new SignerCertificateStep(policy, trust),
                new DssValidationStep(new IcpBrasilCertificateVerifiers(trust, CertificateVerifierFactory.offline(ocsp, null)),
                        policy),
                new TimestampValidationStep(policy),
                new ValidationOutcomeStep());
        ValidationContext context = ValidationContext.builder()
                .signatureJson(artifact.signature())
                .bundleJson(artifact.bundle())
                .provenanceJson(artifact.provenance())
                .referenceTimestamp(artifact.reference())
                .policyIdentifierUri(Policy020.POLICY_URI)
                .operationalConfig(TestConfigs.operational())
                .build();
        for (ValidationStep step : steps) {
            StepResult<ValidationContext> result;
            try {
                result = step.execute(context);
            } catch (Exception e) {
                return INTERNAL_ERROR;
            }
            if (result instanceof StepResult.Failure<ValidationContext> failure) {
                return failure.code().getCode();
            }
            context = result.context();
        }
        return context.getOperationOutcome().issue().getFirst().details().coding().getFirst().code();
    }

    private static String diagnosticsOf(Artifact artifact) {
        ValidationContext context = ValidationContext.builder()
                .signatureJson(artifact.signature())
                .bundleJson(artifact.bundle())
                .provenanceJson(artifact.provenance())
                .referenceTimestamp(artifact.reference())
                .policyIdentifierUri(Policy020.POLICY_URI)
                .operationalConfig(TestConfigs.operational())
                .build();
        context = new SignatureBindingStep().execute(context).context();
        context = new JwsStructureStep().execute(context).context();
        context = new SignerCertificateStep(policy, trust).execute(context).context();
        return new ValidationOutcomeStep().execute(context).context().getOperationOutcome().issue().getFirst().diagnostics();
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static JsonObject bundle() {
        return LosslessJson.parseObject(SignedArtifactFixture.BUNDLE);
    }

    private static JsonObject provenance() {
        return LosslessJson.parseObject(SignedArtifactFixture.PROVENANCE);
    }

    private static String payload(JsonObject bundle, JsonObject provenance) {
        return URL.encodeToString(FramedContentDigest.sha256(SignedContentRules.orderedParts(bundle, provenance)));
    }

    private static String x5c(List<X509Certificate> chain) {
        List<String> items = new ArrayList<>();
        for (X509Certificate certificate : chain) {
            items.add("\"" + STD.encodeToString(encoded(certificate)) + "\"");
        }
        return "[" + String.join(",", items) + "]";
    }

    private static String thumbprint(X509Certificate certificate) {
        return URL.encodeToString(sha256(encoded(certificate)));
    }

    /** Protected header da política 0.2.0 com os membros na ordem do assinador. */
    private static String header(List<X509Certificate> chain, String iatLexical) {
        return "{\"alg\":\"RS256\",\"x5t#S256\":\"" + thumbprint(chain.getFirst()) + "\",\"x5c\":" + x5c(chain)
                + ",\"iat\":" + iatLexical
                + ",\"sigPId\":{\"id\":{\"id\":\"" + Policy020.POLICY_URI + "\"}}"
                + ",\"srCms\":[{\"commId\":{\"id\":\"urn:oid:" + Policy020.VERIFICATION_SIGNATURE_OID + "\"}}]}";
    }

    private static String header(long iat) {
        return header(pki.chain(), Long.toString(iat));
    }

    private static Jws sign(String headerJson, String payload, PrivateKey key) {
        String protectedB64 = URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        return new Jws(protectedB64, payload, rs256(key, protectedB64 + "." + payload));
    }

    private static Jws sign(String headerJson) {
        return sign(headerJson, payload(bundle(), provenance()), pki.leafKeys.getPrivate());
    }

    private static String rs256(PrivateKey key, String input) {
        try {
            Signature signer = Signature.getInstance("SHA256withRSA");
            signer.initSign(key);
            signer.update(input.getBytes(StandardCharsets.US_ASCII));
            return URL.encodeToString(signer.sign());
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Signature FHIR + Provenance final com o JWS informado. */
    private static Artifact artifact(String jws, long iat, String cpf, JsonObject bundle, JsonObject provenance) {
        String signature = "{\"type\":[{\"system\":\"" + Policy020.SIGNATURE_TYPE_SYSTEM + "\",\"code\":\""
                + Policy020.VERIFICATION_SIGNATURE_OID + "\"}],\"when\":\"" + Instant.ofEpochSecond(iat)
                + "\",\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"" + cpf + "\"}},"
                + "\"sigFormat\":\"" + Policy020.SIG_FORMAT + "\",\"targetFormat\":\"" + Policy020.TARGET_FORMAT + "\","
                + "\"data\":\"" + STD.encodeToString(jws.getBytes(StandardCharsets.UTF_8)) + "\"}";
        JsonObject parsed = LosslessJson.parseObject(signature);
        return new Artifact(parsed, bundle, provenance.with("signature", new JsonArray(List.of(parsed))), now() + 2);
    }

    private static Artifact artifact(String jws, long iat) {
        return artifact(jws, iat, TestPki.TEST_CPF, bundle(), provenance());
    }

    /** Artefato JAdES-B-B legítimo (assinado pela chave do titular). */
    private static Artifact legitimateBaselineB() {
        long iat = now() - 5;
        return artifact(sign(header(iat)).json(), iat);
    }

    private static String sigTst(byte[] token) {
        return "{\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":\"" + STD.encodeToString(token) + "\"}]}}]}";
    }

    private static byte[] tokenOver(String signatureText, Date genTime) {
        return pki.timestampToken(sha256(signatureText.getBytes(StandardCharsets.US_ASCII)), TokenOptions.at(genTime));
    }

    private static Date at(long epochSeconds) {
        return new Date(epochSeconds * 1000);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] encoded(X509Certificate certificate) {
        try {
            return certificate.getEncoded();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static KeyPair rsa(int bits) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(bits);
            return generator.generateKeyPair();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    /** Certificado com identidade CPF ICP-Brasil (SERIALNUMBER e SAN otherName 2.16.76.1.3.1). */
    private static X509Certificate certificate(KeyPair subject, X509Certificate issuer, PrivateKey issuerKey, String cpf,
                                               long notBefore, long notAfter, String policyOid, int keyUsage, boolean ca) {
        try {
            X500Name subjectName = new X500Name("CN=Atacante:" + cpf + ",SERIALNUMBER=" + cpf);
            X500Name issuerName = issuer == null ? subjectName : X500Name.getInstance(issuer.getSubjectX500Principal().getEncoded());
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuerName,
                    BigInteger.valueOf(SERIAL.incrementAndGet()), at(notBefore), at(notAfter), subjectName, subject.getPublic());
            builder.addExtension(Extension.certificatePolicies, false,
                    new CertificatePolicies(new PolicyInformation(new ASN1ObjectIdentifier(policyOid))));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(keyUsage));
            if (ca) {
                builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            }
            ASN1EncodableVector otherName = new ASN1EncodableVector();
            otherName.add(new ASN1ObjectIdentifier("2.16.76.1.3.1"));
            otherName.add(new DERTaggedObject(true, 0, new DERUTF8String("01011990" + cpf + "000000000000000000")));
            builder.addExtension(Extension.subjectAlternativeName, false,
                    new GeneralNames(new GeneralName(GeneralName.otherName, new DERSequence(otherName))));
            return new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey)));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static X509Certificate leafFromTestCa(KeyPair keys, long notBefore, long notAfter, String policyOid,
                                                  int keyUsage, boolean ca) {
        return certificate(keys, pki.caCert, pki.caKeys.getPrivate(), TestPki.TEST_CPF, notBefore, notAfter, policyOid,
                keyUsage, ca);
    }

    /** Artefato B-B assinado por outra chave/cadeia, com {@code who} igual ao CPF de teste. */
    private static Artifact signedBy(KeyPair keys, List<X509Certificate> chain, long iat) {
        String jws = sign(header(chain, Long.toString(iat)), payload(bundle(), provenance()), keys.getPrivate()).json();
        return artifact(jws, iat);
    }

    private static JsonObject object(String json) {
        return LosslessJson.parseObject(json);
    }

    // ---------------------------------------------------------------------------------------------
    // Controles: o artefato legítimo forjado pelo harness é aceito
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldAcceptLegitimateBaselineBWhenProducedByHarness() {
        assertThat(validate(legitimateBaselineB())).isEqualTo(SUCCESS);
    }

    @Test
    void shouldAcceptLegitimateBaselineTWhenProducedByHarness() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(tokenOver(jws.signature(), at(iat)))), iat))).isEqualTo(SUCCESS);
    }

    @Test
    void shouldAcceptArtifactProducedBySigningPipeline() {
        var signed = SignedArtifactFixture.sign(pki, policy);

        assertThat(validate(new Artifact(object(signed.signatureJson()), bundle(), object(signed.provenanceJson()),
                now() + 2))).isEqualTo(SUCCESS);
    }

    // ---------------------------------------------------------------------------------------------
    // Protected header (reassinado com a chave legítima do titular)
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectAlgNoneWhenSignatureIsEmpty() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("\"RS256\"", "\"none\"");
        Jws jws = new Jws(URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8)), payload(bundle(), provenance()), "");

        assertThat(validate(artifact(jws.json(), iat))).isEqualTo(SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM.getCode());
    }

    @Test
    void shouldRejectHs256KeyedWithSignerPublicKeyWhenAlgorithmConfusionIsAttempted() throws Exception {
        long iat = now() - 5;
        String headerJson = header(iat).replace("\"RS256\"", "\"HS256\"");
        String protectedB64 = URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = payload(bundle(), provenance());
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(pki.leafCert.getPublicKey().getEncoded(), "HmacSHA256"));
        String tag = URL.encodeToString(mac.doFinal((protectedB64 + "." + payload).getBytes(StandardCharsets.US_ASCII)));

        assertThat(validate(artifact(new Jws(protectedB64, payload, tag).json(), iat)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM.getCode());
    }

    @Test
    void shouldRejectPs256WhenSignedWithSameRsaKey() throws Exception {
        long iat = now() - 5;
        String headerJson = header(iat).replace("\"RS256\"", "\"PS256\"");
        String protectedB64 = URL.encodeToString(headerJson.getBytes(StandardCharsets.UTF_8));
        String payload = payload(bundle(), provenance());
        Signature pss = Signature.getInstance("RSASSA-PSS");
        pss.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        pss.initSign(pki.leafKeys.getPrivate());
        pss.update((protectedB64 + "." + payload).getBytes(StandardCharsets.US_ASCII));

        assertThat(validate(artifact(new Jws(protectedB64, payload, URL.encodeToString(pss.sign())).json(), iat)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM.getCode());
    }

    @Test
    void shouldRejectCritAndB64WhenAddedToProtectedHeader() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("{\"alg\"", "{\"crit\":[\"b64\"],\"b64\":false,\"alg\"");

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectKidWhenAddedToProtectedHeader() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("{\"alg\"", "{\"kid\":\"outra-chave\",\"alg\"");

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectTypAndCtyWhenAddedToProtectedHeader() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("{\"alg\"", "{\"typ\":\"jose+json\",\"cty\":\"json\",\"alg\"");

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectSigTstWhenPlacedInProtectedHeader() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("{\"alg\"", "{\"sigTst\":{\"tstTokens\":[]},\"alg\"");

        assertThat(validate(artifact(sign(headerJson).json(), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_COMPONENT_PLACEMENT_INVALID.getCode());
    }

    @Test
    void shouldRejectDuplicateAlgWhenProtectedHeaderHasRepeatedMember() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("{\"alg\":\"RS256\"", "{\"alg\":\"none\",\"alg\":\"RS256\"");

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectProtectedHeaderWhenPrefixedWithBom() {
        long iat = now() - 5;
        String headerJson = "﻿" + header(iat);

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectThumbprintWhenItPointsToIssuerCertificate() {
        long iat = now() - 5;
        String headerJson = header(iat).replace(thumbprint(pki.leafCert), thumbprint(pki.caCert));

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectMissingThumbprintWhenOnlyX5cIsPresent() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("\"x5t#S256\":\"" + thumbprint(pki.leafCert) + "\",", "");

        assertThat(validate(artifact(sign(headerJson).json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectReorderedX5cWhenRootComesFirst() {
        long iat = now() - 5;
        String headerJson = header(List.of(pki.caCert, pki.leafCert), Long.toString(iat))
                .replace(thumbprint(pki.caCert), thumbprint(pki.leafCert));

        assertThat(validate(artifact(sign(headerJson).json(), iat)))
                .isIn(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode(), SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectX5cWhenUnrelatedCertificateIsAppended() {
        long iat = now() - 5;
        List<X509Certificate> chain = List.of(pki.leafCert, pki.caCert, TestPki.create().caCert);

        assertThat(validate(artifact(sign(header(chain, Long.toString(iat))).json(), iat)))
                .isIn(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectX5cWhenOnlyLeafIsPresent() {
        long iat = now() - 5;

        assertThat(validate(artifact(sign(header(List.of(pki.leafCert), Long.toString(iat))).json(), iat)))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode());
    }

    @Test
    void shouldRejectVictimCertificateInX5cWhenSignedWithAttackerKey() {
        long iat = now() - 5;
        Jws jws = sign(header(iat), payload(bundle(), provenance()), rsa(2048).getPrivate());

        assertThat(validate(artifact(jws.json(), iat)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectSigPIdWhenPolicyUriIsSubstituted() {
        long iat = now() - 5;
        String headerJson = header(iat).replace(Policy020.POLICY_URI, Policy020.POLICY_URI.replace("0.2.0", "0.1.0"));

        assertThat(validate(artifact(sign(headerJson).json(), iat)))
                .isEqualTo(SignatureExceptionCode.POLICY_SIGNATURE_POLICY_ID_INVALID.getCode());
    }

    @Test
    void shouldRejectSigPIdWhenExtraMembersAreAdded() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("\"" + Policy020.POLICY_URI + "\"}}",
                "\"" + Policy020.POLICY_URI + "\"},\"hashAV\":\"S256\",\"hashV\":\"AAAA\"}");

        assertThat(validate(artifact(sign(headerJson).json(), iat)))
                .isEqualTo(SignatureExceptionCode.POLICY_SIGNATURE_POLICY_ID_INVALID.getCode());
    }

    @Test
    void shouldRejectSrCmsWhenCommitmentIsAuthorSignature() {
        long iat = now() - 5;
        String headerJson = header(iat).replace("urn:oid:" + Policy020.VERIFICATION_SIGNATURE_OID, "urn:oid:1.2.840.10065.1.12.1.1");

        assertThat(validate(artifact(sign(headerJson).json(), iat)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectIatWhenItHasFractionOrExponent() {
        long iat = now() - 5;

        assertThat(validate(artifact(sign(header(pki.chain(), iat + ".0")).json(), iat)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
        assertThat(validate(artifact(sign(header(pki.chain(), "1.7e9")).json(), 1_700_000_000L)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
    }

    @Test
    void shouldRejectIatWhenItIsAString() {
        long iat = now() - 5;

        assertThat(validate(artifact(sign(header(pki.chain(), "\"" + iat + "\"")).json(), iat)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
    }

    @Test
    void shouldRejectIatWithTemporalCodeWhenItOverflowsLong() {
        long when = now() - 5;

        assertThat(validate(artifact(sign(header(pki.chain(), "9999999999999999999")).json(), when)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
    }

    @Test
    void shouldNotAcceptIatWhenItOverflowsLong() {
        long when = now() - 5;

        assertThat(validate(artifact(sign(header(pki.chain(), "9999999999999999999")).json(), when))).isNotEqualTo(SUCCESS);
    }

    @Test
    void shouldRejectIatWhenItIsAfterReferenceTimestamp() {
        long iat = now() + 120;

        assertThat(validate(artifact(sign(header(iat)).json(), iat).withReference(now())))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
    }

    @Test
    void shouldRejectIatWhenItIsBeforeCertificateValidity() {
        long iat = TestPki.CERT_START - 3600;

        assertThat(validate(artifact(sign(header(iat)).json(), iat)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD.getCode());
    }

    @Test
    void shouldRejectSignatureWhenWhenDiffersFromIat() {
        long iat = now() - 5;
        Artifact artifact = artifact(sign(header(iat)).json(), iat)
                .withSignature(s -> s.with("when", new JsonString(Instant.ofEpochSecond(iat - 1).toString())));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID.getCode());
    }

    // ---------------------------------------------------------------------------------------------
    // Estrutura do JWS e header não protegido
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectJwsWhenTwoSignaturesArePresent() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String entry = "{\"protected\":\"" + jws.protectedB64() + "\",\"signature\":\"" + jws.signature() + "\"}";
        String twoSignatures = "{\"payload\":\"" + jws.payload() + "\",\"signatures\":[" + entry + "," + entry + "]}";

        assertThat(validate(artifact(twoSignatures, iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectFlattenedSerializationWhenSubmittedInsteadOfGeneral() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String flattened = "{\"payload\":\"" + jws.payload() + "\",\"protected\":\"" + jws.protectedB64()
                + "\",\"signature\":\"" + jws.signature() + "\"}";

        assertThat(validate(artifact(flattened, iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectCompactSerializationWhenSubmittedInsteadOfGeneral() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.protectedB64() + "." + jws.payload() + "." + jws.signature(), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectDetachedPayloadWhenPayloadIsEmpty() {
        long iat = now() - 5;
        Jws jws = sign(header(iat), "", pki.leafKeys.getPrivate());

        assertThat(validate(artifact(jws.json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectAttachedPayloadWhenItCarriesTheResourcesInsteadOfTheDigest() {
        long iat = now() - 5;
        String payload = URL.encodeToString(SignedArtifactFixture.BUNDLE.getBytes(StandardCharsets.UTF_8));

        assertThat(validate(artifact(sign(header(iat), payload, pki.leafKeys.getPrivate()).json(), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    @Test
    void shouldRejectUnprotectedHeaderWhenBaselineBCarriesArbitraryMember() {
        long iat = now() - 5;

        assertThat(validate(artifact(sign(header(iat)).json("{\"kid\":\"x\"}"), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID.getCode());
    }

    @Test
    void shouldRejectEtsiUWhenItContainsExtraComponentBesideSigTst() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String token = STD.encodeToString(tokenOver(jws.signature(), at(iat)));
        String header = "{\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":\"" + token + "\"}]}},{\"rVals\":{}}]}";

        assertThat(validate(artifact(jws.json(header), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID.getCode());
    }

    @Test
    void shouldRejectEtsiUWhenTwoTimestampTokensArePresent() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String token = STD.encodeToString(tokenOver(jws.signature(), at(iat)));
        String header = "{\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":\"" + token + "\"},{\"val\":\"" + token + "\"}]}}]}";

        assertThat(validate(artifact(jws.json(header), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID.getCode());
    }

    @Test
    void shouldRejectEtsiUWhenComponentIsBase64UrlEncoded() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String component = "{\"sigTst\":{\"tstTokens\":[{\"val\":\"" + STD.encodeToString(tokenOver(jws.signature(), at(iat))) + "\"}]}}";
        String header = "{\"etsiU\":[\"" + URL.encodeToString(component.getBytes(StandardCharsets.UTF_8)) + "\"]}";

        assertThat(validate(artifact(jws.json(header), iat)))
                .isEqualTo(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID.getCode());
    }

    @Test
    void shouldRejectJwsWhenSignatureObjectHasDuplicateMembers() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        String duplicated = jws.json().replace("\"signature\":\"", "\"signature\":\"AAAA\",\"signature\":\"");

        assertThat(validate(artifact(duplicated, iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

    // ---------------------------------------------------------------------------------------------
    // JAdES-B-T: carimbo do tempo
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectTimestampWhenReplayedFromAnotherSignature() {
        long iat = now() - 5;
        Jws other = sign(header(iat - 1));
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(tokenOver(other.signature(), at(iat)))), iat)))
                .isIn(SignatureExceptionCode.TSA_MESSAGE_IMPRINT_MISMATCH.getCode(),
                        SignatureExceptionCode.TSA_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectTimestampWhenImprintIsOverPayloadInsteadOfSignature() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(tokenOver(jws.payload(), at(iat)))), iat)))
                .isIn(SignatureExceptionCode.TSA_MESSAGE_IMPRINT_MISMATCH.getCode(),
                        SignatureExceptionCode.TSA_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectTimestampWhenGenTimeIsOutsideIatWindow() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(tokenOver(jws.signature(), at(iat - 1000)))), iat)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS.getCode());
    }

    @Test
    void shouldRejectTimestampWhenGenTimeIsAfterReferenceTimestamp() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(tokenOver(jws.signature(), at(iat + 200)))), iat)))
                .isIn(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS.getCode(),
                        SignatureExceptionCode.TSA_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectTimestampWhenTsaPolicyIsNotAccepted() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        byte[] token = pki.timestampToken(sha256(jws.signature().getBytes(StandardCharsets.US_ASCII)),
                TokenOptions.at(at(iat)).withPolicy("1.2.3.4.5"));

        assertThat(validate(artifact(jws.json(sigTst(token)), iat)))
                .isEqualTo(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED.getCode());
    }

    @Test
    void shouldRejectTimestampWhenAccuracyExceedsPolicy() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));
        byte[] token = pki.timestampToken(sha256(jws.signature().getBytes(StandardCharsets.US_ASCII)),
                TokenOptions.at(at(iat)).withAccuracy(120));

        assertThat(validate(artifact(jws.json(sigTst(token)), iat))).isEqualTo(SignatureExceptionCode.TSA_INVALID_TOKEN.getCode());
    }

    @Test
    void shouldRejectTimestampWhenTokenIsGarbage() {
        long iat = now() - 5;
        Jws jws = sign(header(iat));

        assertThat(validate(artifact(jws.json(sigTst(new byte[]{0x30, 0x03, 0x02, 0x01, 0x01})), iat)))
                .isNotEqualTo(SUCCESS).isNotEqualTo(INTERNAL_ERROR);
    }

    @Test
    void shouldReportBaselineBWhenTimestampIsStrippedFromBaselineT() {
        Artifact stripped = legitimateBaselineB();

        assertThat(validate(stripped)).isEqualTo(SUCCESS);
        assertThat(diagnosticsOf(stripped)).contains("JAdES-B-B").doesNotContain("JAdES-B-T");
    }

    // ---------------------------------------------------------------------------------------------
    // Conteúdo assinado: Bundle e Provenance.target
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectSignedResourceWhenValueIsChanged() {
        assertThat(validate(legitimateBaselineB().withBundle(SignedArtifactFixture.BUNDLE.replace("female", "male"))))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectSignedResourceWhenDecimalLexicalFormIsChanged() {
        assertThat(validate(legitimateBaselineB().withBundle(SignedArtifactFixture.BUNDLE.replace("13.50", "1.350e1"))))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectSignedResourceWhenMemberIsAdded() {
        String bundle = SignedArtifactFixture.BUNDLE.replace("\"gender\":\"female\"", "\"gender\":\"female\",\"deceasedBoolean\":true");

        assertThat(validate(legitimateBaselineB().withBundle(bundle)))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectBundleWhenSignedResourceHasDuplicateMembers() {
        String bundle = SignedArtifactFixture.BUNDLE.replace("\"gender\":\"female\"", "\"gender\":\"female\",\"gender\":\"male\"");

        assertThatThrownBy(() -> LosslessJson.parseObject(bundle)).isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldRejectProvenanceWhenTargetOrderIsSwapped() {
        Artifact artifact = legitimateBaselineB().withProvenance(p -> p.with("target", new JsonArray(List.of(
                object("{\"reference\":\"" + SignedArtifactFixture.U1 + "\"}"),
                object("{\"reference\":\"" + SignedArtifactFixture.U2 + "\"}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectProvenanceWhenATargetIsRemoved() {
        Artifact artifact = legitimateBaselineB().withProvenance(p -> p.with("target", new JsonArray(List.of(
                object("{\"reference\":\"" + SignedArtifactFixture.U2 + "\"}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    void shouldRejectTargetWhenUuidIsUppercased() {
        String upper = SignedArtifactFixture.U1.replace("3fa85f64", "3FA85F64");
        Artifact artifact = legitimateBaselineB()
                .withBundle(SignedArtifactFixture.BUNDLE.replace(SignedArtifactFixture.U1, upper))
                .withProvenance(p -> p.with("target", new JsonArray(List.of(
                        object("{\"reference\":\"" + SignedArtifactFixture.U2 + "\"}"),
                        object("{\"reference\":\"" + upper + "\"}")))));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROVENANCE_TARGET_INVALID.getCode(),
                SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED.getCode());
    }

    @Test
    void shouldRejectBundleWhenSignedFullUrlIsDuplicatedWithAlternativeResource() {
        String evil = ",{\"fullUrl\":\"" + SignedArtifactFixture.U1
                + "\",\"resource\":{\"resourceType\":\"Patient\",\"id\":\"p1\",\"gender\":\"male\"}}]}";
        String bundle = SignedArtifactFixture.BUNDLE.substring(0, SignedArtifactFixture.BUNDLE.length() - 2) + evil;

        assertThat(validate(legitimateBaselineB().withBundle(bundle)))
                .isEqualTo(SignatureExceptionCode.FORMAT_DUPLICATE_FULLURL.getCode());
    }

    @Test
    void shouldRejectSignedResourceWhenUnicodeLookalikeReplacesAscii() {
        // "female" com 'а' cirílico: visualmente igual, bytes diferentes
        assertThat(validate(legitimateBaselineB().withBundle(SignedArtifactFixture.BUNDLE.replace("female", "femаle"))))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V3: recurso referenciado por um recurso assinado, mas fora de Provenance.target, pode ser trocado sem invalidar a assinatura")
    void shouldRejectReferencedResourceWhenItIsOutsideTargetsAndIsReplaced() {
        // Provenance assina só a Observation (U2), que referencia o Patient (U1) não assinado
        JsonObject provenance = provenance().with("target", new JsonArray(List.of(
                object("{\"reference\":\"" + SignedArtifactFixture.U2 + "\"}"))));
        long iat = now() - 5;
        Jws jws = sign(header(iat), payload(bundle(), provenance), pki.leafKeys.getPrivate());
        Artifact artifact = artifact(jws.json(), iat, TestPki.TEST_CPF, bundle(), provenance);
        assertThat(validate(artifact)).isEqualTo(SUCCESS);

        Artifact swappedPatient = artifact.withBundle(SignedArtifactFixture.BUNDLE.replace("\"gender\":\"female\"",
                "\"gender\":\"male\",\"name\":[{\"text\":\"Outro Paciente\"}]"));

        assertThat(validate(swappedPatient)).isNotEqualTo(SUCCESS);
    }

    // ---------------------------------------------------------------------------------------------
    // Signature FHIR e vínculo com Provenance (sem nova assinatura: metadados fora do JWS)
    // ---------------------------------------------------------------------------------------------

    @Test
    @Disabled("VULN-V2: Signature.onBehalfOf (0..0 no perfil) aceito — metadado não assinado altera a representação")
    void shouldRejectSignatureWhenOnBehalfOfIsInjected() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("onBehalfOf",
                object("{\"identifier\":{\"system\":\"urn:brasil:cnpj\",\"value\":\"11222333000181\"}}")));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED.getCode(),
                SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V2: Signature.who.display (0..0 no perfil) aceito — nome arbitrário exibido junto à assinatura válida")
    void shouldRejectSignatureWhenWhoDisplayIsInjected() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("who",
                s.object("who").orElseThrow().with("display", new JsonString("Dr. Outro Médico"))));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED.getCode(),
                SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V2: Signature.who.reference (0..0 no perfil) aceito — aponta a assinatura para outro Practitioner")
    void shouldRejectSignatureWhenWhoReferenceIsInjected() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("who",
                s.object("who").orElseThrow().with("reference", new JsonString("Practitioner/outro"))));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED.getCode(),
                SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V2: Signature.who.identifier.period/assigner (0..0 no perfil) aceitos quando também presentes no agent")
    void shouldRejectSignatureWhenIdentifierCarriesForbiddenMembers() {
        Artifact base = legitimateBaselineB();
        JsonObject identifier = base.signature().object("who").orElseThrow().object("identifier").orElseThrow()
                .with("assigner", object("{\"display\":\"Conselho Falso\"}"));
        Artifact artifact = base
                .withSignature(s -> s.with("who", s.object("who").orElseThrow().with("identifier", identifier)))
                .withProvenance(p -> p.with("agent", new JsonArray(List.of(object("{\"who\":{\"identifier\":"
                        + LosslessJson.write(identifier) + "}}")))));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED.getCode(),
                SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V2: membro desconhecido em Signature aceito (não é instância FHIR R4 válida do perfil)")
    void shouldRejectSignatureWhenUnknownMemberIsInjected() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("aprovadoPor", new JsonString("Diretor")));

        assertThat(validate(artifact)).isIn(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED.getCode(),
                SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectSignatureWhenTypeHasTwoCodings() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("type", new JsonArray(List.of(
                s.array("type").orElseThrow().items().getFirst(),
                object("{\"system\":\"urn:iso-astm:E1762-95:2013\",\"code\":\"1.2.840.10065.1.12.1.1\"}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectSignatureWhenWhoIdentifierIsAnotherPerson() {
        Artifact base = legitimateBaselineB();
        JsonObject identifier = object("{\"system\":\"urn:brasil:cpf\",\"value\":\"" + OTHER_CPF + "\"}");
        Artifact artifact = base
                .withSignature(s -> s.with("who", object("{\"identifier\":" + LosslessJson.write(identifier) + "}")))
                .withProvenance(p -> p.with("agent", new JsonArray(List.of(object("{\"who\":{\"identifier\":"
                        + LosslessJson.write(identifier) + "}}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectSignatureWhenCpfSystemIsSwappedForCnpj() {
        Artifact base = legitimateBaselineB();
        JsonObject identifier = object("{\"system\":\"urn:brasil:cnpj\",\"value\":\"" + TestPki.TEST_CPF + "\"}");
        Artifact artifact = base
                .withSignature(s -> s.with("who", object("{\"identifier\":" + LosslessJson.write(identifier) + "}")))
                .withProvenance(p -> p.with("agent", new JsonArray(List.of(object("{\"who\":{\"identifier\":"
                        + LosslessJson.write(identifier) + "}}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectProvenanceWhenSignatureDiffersFromInput() {
        Artifact base = legitimateBaselineB();
        Artifact artifact = new Artifact(base.signature(), base.bundle(), base.provenance().with("signature", new JsonArray(List.of(
                base.signature().with("when", new JsonString("2026-01-01T00:00:00Z"))))), base.reference());

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectProvenanceWhenItHasTwoSignatures() {
        Artifact base = legitimateBaselineB();
        Artifact artifact = base.withProvenance(p -> p.with("signature", new JsonArray(List.of(base.signature(), base.signature()))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID.getCode());
    }

    @Test
    void shouldRejectProvenanceWhenNoAgentMatchesSigner() {
        Artifact artifact = legitimateBaselineB().withProvenance(p -> p.with("agent", new JsonArray(List.of(
                object("{\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"" + OTHER_CPF + "\"}}}")))));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectSignatureDataWhenItUsesMimeLineBreaks() {
        Artifact base = legitimateBaselineB();
        String data = base.signature().string("data").orElseThrow();
        String mime = data.substring(0, 76) + "\r\n" + data.substring(76);

        assertThat(validate(base.withSignature(s -> s.with("data", new JsonString(mime)))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID.getCode());
    }

    @Test
    void shouldRejectSignatureDataWhenItIsBase64Url() {
        Artifact base = legitimateBaselineB();
        String data = base.signature().string("data").orElseThrow();
        String url = data.replace('+', '-').replace('/', '_').replace("=", "");

        assertThat(data).isNotEqualTo(url);
        assertThat(validate(base.withSignature(s -> s.with("data", new JsonString(url)))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID.getCode());
    }

    @Test
    void shouldRejectSignatureDataWhenJwsIsPrefixedWithBom() {
        Artifact base = legitimateBaselineB();
        byte[] jws = Base64.getDecoder().decode(base.signature().string("data").orElseThrow());
        byte[] withBom = new byte[jws.length + 3];
        withBom[0] = (byte) 0xEF;
        withBom[1] = (byte) 0xBB;
        withBom[2] = (byte) 0xBF;
        System.arraycopy(jws, 0, withBom, 3, jws.length);

        assertThat(validate(base.withSignature(s -> s.with("data", new JsonString(STD.encodeToString(withBom))))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID.getCode());
    }

    @Test
    void shouldRejectSignatureWhenSigFormatIsChanged() {
        Artifact artifact = legitimateBaselineB().withSignature(s -> s.with("sigFormat", new JsonString("application/jws")));

        assertThat(validate(artifact)).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldAcceptChangeInUnsignedProvenanceMetadataByIgDesign() {
        // Somente Ti/Ri entram no artefato enquadrado: recorded/agent extra não são protegidos (risco residual)
        Artifact artifact = legitimateBaselineB().withProvenance(p -> p
                .with("recorded", new JsonString("1999-01-01T00:00:00Z"))
                .with("agent", new JsonArray(List.of(p.array("agent").orElseThrow().items().getFirst(),
                        object("{\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"" + OTHER_CPF + "\"}}}")))));

        assertThat(validate(artifact)).isEqualTo(SUCCESS);
    }

    // ---------------------------------------------------------------------------------------------
    // Certificado do signatário e cadeia
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectSelfSignedLeafWhenItCarriesIcpBrasilPolicyAndIdentity() {
        KeyPair keys = rsa(2048);
        X509Certificate self = certificate(keys, null, keys.getPrivate(), TestPki.TEST_CPF, TestPki.CERT_START,
                TestPki.CERT_END, "2.16.76.1.2.3.1", KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(self, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED.getCode());
        assertThat(validate(signedBy(keys, List.of(self), now() - 5)))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode());
    }

    @Test
    void shouldRejectLeafWhenIssuedByRogueRootWithSameName() {
        KeyPair rogueKeys = rsa(2048);
        X509Certificate rogueRoot;
        try {
            X500Name name = X500Name.getInstance(pki.caCert.getSubjectX500Principal().getEncoded());
            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(name, BigInteger.ONE,
                    at(TestPki.CERT_START), at(TestPki.CERT_END), name, rogueKeys.getPublic());
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            rogueRoot = new JcaX509CertificateConverter().getCertificate(
                    builder.build(new JcaContentSignerBuilder("SHA256withRSA").build(rogueKeys.getPrivate())));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        KeyPair keys = rsa(2048);
        X509Certificate leaf = certificate(keys, rogueRoot, rogueKeys.getPrivate(), TestPki.TEST_CPF, TestPki.CERT_START,
                TestPki.CERT_END, "2.16.76.1.2.3.1", KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, rogueRoot), now() - 5)))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL.getCode());
    }

    @Test
    void shouldRejectChainWhenRootIsTrustedButNotInAllowlist() {
        TestPki other = TestPki.create();
        TrustMaterialSource both = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert, other.caCert)));
        long iat = now() - 5;
        Artifact artifact = signedBy(other.leafKeys, other.chain(), iat);

        assertThat(validate(artifact, policy, both, other.ocspGoodSource()))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode());
    }

    @Test
    void shouldRejectChainWhenRootIsNotInAcervo() {
        TestPki other = TestPki.create();

        assertThat(validate(signedBy(other.leafKeys, other.chain(), now() - 5), policy, trust, other.ocspGoodSource()))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL.getCode());
    }

    @Test
    void shouldRejectCaCertificateWhenUsedAsSigner() {
        KeyPair keys = rsa(2048);
        X509Certificate subCa = leafFromTestCa(keys, TestPki.CERT_START, TestPki.CERT_END, "2.16.76.1.2.3.1",
                KeyUsage.digitalSignature | KeyUsage.keyCertSign, true);

        assertThat(validate(signedBy(keys, List.of(subCa, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode(),
                        SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectLeafWhenKeyUsageLacksDigitalSignature() {
        KeyPair keys = rsa(2048);
        X509Certificate leaf = leafFromTestCa(keys, TestPki.CERT_START, TestPki.CERT_END, "2.16.76.1.2.3.1",
                KeyUsage.keyEncipherment, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode(),
                        SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectLeafWhenPolicyOidIsA1() {
        KeyPair keys = rsa(2048);
        X509Certificate leaf = leafFromTestCa(keys, TestPki.CERT_START, TestPki.CERT_END, "2.16.76.1.2.1.1",
                KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED.getCode(),
                        SignatureExceptionCode.CERT_NOT_ICP_BRASIL.getCode());
    }

    @Test
    void shouldRejectLeafWhenKeyIsRsa1024() {
        KeyPair keys = rsa(1024);
        X509Certificate leaf = leafFromTestCa(keys, TestPki.CERT_START, TestPki.CERT_END, "2.16.76.1.2.3.1",
                KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.CERT_WEAK_KEY.getCode(),
                        SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED.getCode());
    }

    @Test
    @Disabled("VULN-V4: folha expirada recusada como VALIDATION.INDETERMINATE (CERTIFICATE_CHAIN_GENERAL_FAILURE), não CERT.EXPIRED")
    void shouldRejectLeafWhenCertificateIsExpired() {
        KeyPair keys = rsa(2048);
        long notBefore = TestPki.CERT_START + 86_400;
        long notAfter = notBefore + 30L * 86_400;
        X509Certificate leaf = leafFromTestCa(keys, notBefore, notAfter, "2.16.76.1.2.3.1", KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), notBefore + 86_400)))
                .isEqualTo(SignatureExceptionCode.CERT_EXPIRED.getCode());
    }

    @Test
    void shouldNotAcceptLeafWhenCertificateIsExpired() {
        KeyPair keys = rsa(2048);
        long notBefore = TestPki.CERT_START + 86_400;
        X509Certificate leaf = leafFromTestCa(keys, notBefore, notBefore + 30L * 86_400, "2.16.76.1.2.3.1",
                KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), notBefore + 86_400))).isNotEqualTo(SUCCESS);
    }

    @Test
    void shouldRejectLeafWhenCertificateIsNotYetValid() {
        KeyPair keys = rsa(2048);
        long notBefore = now() + 86_400;
        X509Certificate leaf = leafFromTestCa(keys, notBefore, TestPki.CERT_END, "2.16.76.1.2.3.1",
                KeyUsage.digitalSignature, false);

        assertThat(validate(signedBy(keys, List.of(leaf, pki.caCert), now() - 5)))
                .isIn(SignatureExceptionCode.TEMPORAL_IAT_OUT_OF_CERT_PERIOD.getCode(),
                        SignatureExceptionCode.CERT_NOT_YET_VALID.getCode());
    }

    @Test
    void shouldRejectLeafWhenCertificateIsRevoked() {
        RevocationSource<OCSP> revoked = TestPki.ocspSource(pki::ocspRevokedFor);

        assertThat(validate(legitimateBaselineB(), policy, trust, revoked)).isEqualTo(SignatureExceptionCode.CERT_REVOKED.getCode());
    }

    @Test
    void shouldRejectBaselineBWhenRevocationIsUnavailable() {
        assertThat(validate(legitimateBaselineB(), policy, trust, TestPki.ocspSource(certificate -> null)))
                .isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN.getCode());
    }

    // ---------------------------------------------------------------------------------------------
    // Robustez / DoS / vazamento de informação
    // ---------------------------------------------------------------------------------------------

    @Test
    void shouldRejectHugeX5cWithoutInternalErrorWhenChainHasManyCertificates() {
        List<X509Certificate> chain = new ArrayList<>();
        chain.add(pki.leafCert);
        for (int i = 0; i < 20; i++) {
            chain.add(TestPki.create().caCert);
        }
        long iat = now() - 5;

        assertThat(validate(artifact(sign(header(chain, Long.toString(iat))).json(), iat)))
                .isIn(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE.getCode(), SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED.getCode());
    }

    @Test
    void shouldRejectDeeplyNestedJsonWithoutStackOverflow() {
        String nested = "[".repeat(100_000) + "]".repeat(100_000);

        assertThatThrownBy(() -> LosslessJson.parse(nested)).isInstanceOf(LosslessJsonException.class);
    }

    @Test
    void shouldRejectDeeplyNestedSignedResourceWithoutInternalError() {
        String deep = "{\"a\":".repeat(900) + "1" + "}".repeat(900);
        String bundle = SignedArtifactFixture.BUNDLE.replace("\"gender\":\"female\"", "\"gender\":\"female\",\"x\":" + deep);

        assertThat(validate(legitimateBaselineB().withBundle(bundle))).isNotEqualTo(SUCCESS).isNotEqualTo(INTERNAL_ERROR);
    }

    @Test
    void shouldNotLeakStackOrExceptionTextWhenProtectedHeaderIsNotJson() {
        long iat = now() - 5;
        String protectedB64 = URL.encodeToString("not-json\u0000<script>".getBytes(StandardCharsets.UTF_8));
        Jws jws = new Jws(protectedB64, payload(bundle(), provenance()), rs256(pki.leafKeys.getPrivate(), protectedB64 + ".x"));

        assertThat(validate(artifact(jws.json(), iat))).isEqualTo(SignatureExceptionCode.FORMAT_JWS_MALFORMED.getCode());
    }

}
