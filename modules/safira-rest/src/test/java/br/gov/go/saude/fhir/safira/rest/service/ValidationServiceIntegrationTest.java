/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Integração da validação JAdES-B-T: assinatura B-B produzida pelo {@link SigningService},
 * estendida a B-T com a TSA local de teste e validada pelo {@link ValidationService} (política
 * TSA e trust store TSA configurados, revogação e acervo da lib substituídos pela PKI de teste).
 */
@SpringBootTest
class ValidationServiceIntegrationTest {

    static final TestPki.FakeTsa TSA = JadesSigningSystemTest.PKI.startFakeTsa();

    @MockitoBean
    PkixCertificateValidator pkixCertificateValidator;

    @MockitoBean
    RevocationService revocationService;

    @MockitoBean
    TrustMaterialSource trustMaterialSource;

    @Autowired
    SigningService signingService;

    @Autowired
    ValidationService validationService;

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) throws Exception {
        JadesSigningSystemTest.policy(registry);
        Path anchors = Files.createTempFile("tsa-anchors", ".pem");
        Files.writeString(anchors, "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                .encodeToString(JadesSigningSystemTest.PKI.caCert.getEncoded())
                + "\n-----END CERTIFICATE-----\n", StandardCharsets.US_ASCII);
        registry.add("safira.policy.tsa-policies.version", () -> "1.0.0");
        registry.add("safira.policy.tsa-policies.policies[0].oid", () -> TestPki.TSA_POLICY_OID);
        registry.add("safira.policy.tsa-policies.policies[0].max-accuracy-seconds", () -> "1");
        registry.add("safira.policy.tsa-policies.policies[0].trust-store.reference", () -> "file:" + anchors);
    }

    @AfterAll
    static void stopTsa() {
        TSA.close();
    }

    @BeforeEach
    void setUp() {
        TestPki pki = JadesSigningSystemTest.PKI;
        when(pkixCertificateValidator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of()));
        when(trustMaterialSource.current()).thenReturn(Optional.of(TrustMaterial.of(List.of(pki.caCert))));
        when(revocationService.lookup(any(), any())).thenAnswer(invocation -> {
            byte[] der = pki.ocspGoodFor(invocation.getArgument(0, X509Certificate.class));
            return new RevocationLookup(new RevocationStatus.Good("OCSP", der), new RevocationEvidence.OcspResponse(der));
        });
    }

    /** Assina (B-B) e estende o JWS a B-T, recompondo Signature e Provenance. */
    private String baselineTValidationBody() throws Exception {
        PipelineResult<?> signed = signingService.sign(
                JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI, Instant.now().getEpochSecond()));
        SigningResult result = (SigningResult) signed.getValue();
        JsonObject signature = LosslessJson.parseObject(result.signatureJson());
        String bb = new String(Base64.getDecoder().decode(signature.string("data").orElseThrow()), StandardCharsets.UTF_8);
        String bt = new JadesExtensionService().extendToBaselineT(bb, TspSources.online(TSA.url(), 10, TestPki.TSA_POLICY_OID));

        JsonObject btSignature = signature.with("data",
                new JsonString(Base64.getEncoder().encodeToString(bt.getBytes(StandardCharsets.UTF_8))));
        JsonObject provenance = LosslessJson.parseObject(result.provenanceJson())
                .with("signature", new JsonArray(List.of(btSignature)));
        // DIVERGENCIA-IG D17: o fim do intervalo do carimbo (genTime + accuracy) deve ser <= V (validar 5.4)
        return SignAndValidateSystemTest.validationBody(LosslessJson.write(btSignature),
                JadesSigningSystemTest.example("bundle.json"), LosslessJson.write(provenance),
                Instant.now().getEpochSecond() + 2);
    }

    @Test
    void shouldValidateJadesBaselineT() throws Exception {
        PipelineResult<OperationOutcome> result = validationService.validate(baselineTValidationBody());

        assertThat(result.getExceptionDetails()).isNull();
        assertThat(result.getValue().issue().getFirst().diagnostics()).contains("JAdES-B-T");
    }

    @Test
    void shouldRejectBaselineTWhenTsaRevocationIsInconclusive() throws Exception {
        String body = baselineTValidationBody();
        doAnswer(invocation -> {
            X509Certificate certificate = invocation.getArgument(0, X509Certificate.class);
            if (certificate.getSubjectX500Principal().getName().contains("Fake TSA")) {
                return RevocationLookup.inconclusive(new RevocationStatus.CrlUnavailable());
            }
            byte[] der = JadesSigningSystemTest.PKI.ocspGoodFor(certificate);
            return new RevocationLookup(new RevocationStatus.Good("OCSP", der), new RevocationEvidence.OcspResponse(der));
        }).when(revocationService).lookup(any(), any());

        PipelineResult<OperationOutcome> result = validationService.validate(body);

        assertThat(result.getExceptionDetails().issue().getFirst().details().coding().getFirst().code())
                .isEqualTo("REVOCATION.CRL-UNAVAILABLE");
    }
}
