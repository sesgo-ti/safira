/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.validation.reports.Reports;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Sistema: {@code POST /assinar} com a pipeline única da política 0.2.0 (JAdES-B-B via DSS),
 * corpo JSON cru e PKIX da lib substituído por mock (PKI de teste fora do acervo ICP-Brasil).
 *
 * <p>O resultado {@code tsa} é coberto no nível dos steps ({@code JadesSigningStepsTest}): a
 * política exige TSA HTTPS e a TSA de teste é HTTP local.
 */
@SpringBootTest
class JadesSigningSystemTest {

    static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";
    static final TestPki PKI = TestPki.create();

    @MockitoBean
    PkixCertificateValidator pkixCertificateValidator;

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        registry.add("safira.policy.accepted-certificate-policies[0].oid", () -> "2.16.76.1.2.3.1");
        registry.add("safira.policy.accepted-certificate-policies[0].type", () -> "A3");
        registry.add("safira.policy.accepted-certificate-policies[0].issuer-sha256", PKI::issuerSha256);
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        when(pkixCertificateValidator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(PKI.leafCert), PKI.caCert, List.of()));
    }

    static String example(String name) throws Exception {
        return Files.readString(Path.of("src/test/resources/examples/politica-0.2.0/" + name), StandardCharsets.UTF_8);
    }

    static String signingBody(String policyUri, long referenceTimestamp) throws Exception {
        return "{\"bundle\":" + example("bundle.json")
                + ",\"provenance\":" + example("provenance.json")
                + ",\"signerCryptoMaterial\":{\"type\":\"PEM\",\"privateKeyBase64\":\"" + PKI.leafKeyPemBase64() + "\"}"
                + ",\"certificateChain\":[\"" + Base64.getEncoder().encodeToString(PKI.leafCert.getEncoded()) + "\"]"
                + ",\"referenceTimestamp\":" + referenceTimestamp
                + ",\"strategy\":\"iat\""
                + ",\"policyIdentifierUri\":\"" + policyUri + "\"}";
    }

    private MvcResult sign(String body) throws Exception {
        return mockMvc.perform(post("/assinar").contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    @Test
    void shouldSignBundleProducingJadesBaselineB() throws Exception {
        MvcResult result = sign(signingBody(POLICY_URI, Instant.now().getEpochSecond()));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        JsonNode response = mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String jws = new String(Base64.getDecoder().decode(response.get("signature").get("data").asText()), StandardCharsets.UTF_8);

        var verifier = CertificateVerifiers.create(List.of(PKI.caCert),
                EvidenceRevocationSources.ocspFromEvidence(List.of(PKI.ocspGoodFor(PKI.leafCert))), null);
        Reports reports = new JadesValidationService().validate(jws, verifier);
        String id = reports.getSimpleReport().getFirstSignatureId();
        assertThat(reports.getSimpleReport().getIndication(id)).isEqualTo(Indication.TOTAL_PASSED);
        assertThat(reports.getSimpleReport().getSignatureFormat(id)).isEqualTo(SignatureLevel.JAdES_BASELINE_B);
    }

    @Test
    void shouldReturnProvenanceCopyWithTheSignature() throws Exception {
        MvcResult result = sign(signingBody(POLICY_URI, Instant.now().getEpochSecond()));

        JsonNode response = mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
        assertThat(result.getResponse().getContentType()).startsWith("application/fhir+json");
        assertThat(response.get("provenance").get("signature")).hasSize(1);
        assertThat(response.get("provenance").get("signature").get(0)).isEqualTo(response.get("signature"));
        assertThat(response.get("signature").get("who").get("identifier").get("value").asText()).isEqualTo(TestPki.TEST_CPF);
    }

    @Test
    void shouldReturn422ForLegacyPolicyUri() throws Exception {
        String legacy = "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";

        MvcResult result = sign(signingBody(legacy, Instant.now().getEpochSecond()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).contains("POLICY.URI-INVALID");
    }

    @Test
    void shouldReturn422ForStaleReferenceTimestamp() throws Exception {
        MvcResult result = sign(signingBody(POLICY_URI, Instant.now().getEpochSecond() - 3600));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).contains("FORMAT.INVALID-TIMESTAMP");
    }

    @Test
    void shouldReturn422ForDuplicateMembers() throws Exception {
        String body = signingBody(POLICY_URI, Instant.now().getEpochSecond())
                .replaceFirst("\"strategy\":\"iat\"", "\"strategy\":\"iat\",\"strategy\":\"iat\"");

        MvcResult result = sign(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(result.getResponse().getContentAsString(StandardCharsets.UTF_8)).contains("FORMAT.BUNDLE-MALFORMED");
    }
}
