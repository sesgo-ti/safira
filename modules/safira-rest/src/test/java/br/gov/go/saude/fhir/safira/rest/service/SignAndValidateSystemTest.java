/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Sistema: {@code POST /assinar} seguido de {@code POST /validar} na política 0.2.0, com os
 * serviços da lib icpbrasil-truststore (PKIX, acervo e revogação) substituídos pela PKI de teste.
 */
@SpringBootTest
class SignAndValidateSystemTest {

    @MockitoBean
    PkixCertificateValidator pkixCertificateValidator;

    @MockitoBean
    RevocationService revocationService;

    @MockitoBean
    TrustMaterialSource trustMaterialSource;

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        JadesSigningSystemTest.policy(registry);
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
        var pki = JadesSigningSystemTest.PKI;
        when(pkixCertificateValidator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of()));
        when(trustMaterialSource.current()).thenReturn(Optional.of(TrustMaterial.of(List.of(pki.caCert))));
        when(revocationService.lookup(any(), any())).thenAnswer(invocation -> {
            byte[] der = pki.ocspGoodFor(invocation.getArgument(0, X509Certificate.class));
            return new RevocationLookup(new RevocationStatus.Good("OCSP", der), new RevocationEvidence.OcspResponse(der));
        });
    }

    private JsonNode signed() throws Exception {
        return signed(Instant.now().getEpochSecond());
    }

    private JsonNode signed(long referenceTimestamp) throws Exception {
        String body = JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI, referenceTimestamp);
        MvcResult result = mockMvc.perform(post("/assinar").contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    static String validationBody(String signature, String bundle, String provenance) {
        return validationBody(signature, bundle, provenance, Instant.now().getEpochSecond());
    }

    static String validationBody(String signature, String bundle, String provenance, long referenceTimestamp) {
        return "{\"signature\":" + signature + ",\"bundle\":" + bundle + ",\"provenance\":" + provenance
                + ",\"referenceTimestamp\":" + referenceTimestamp
                + ",\"policyIdentifierUri\":\"" + JadesSigningSystemTest.POLICY_URI + "\"}";
    }

    private MvcResult validate(String body) throws Exception {
        return mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    private String validateAndGetCode(String body, int expectedStatus) throws Exception {
        MvcResult result = validate(body);
        assertThat(result.getResponse().getStatus()).isEqualTo(expectedStatus);
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    @Test
    void shouldValidateSignatureCreatedWithIatStrategy() throws Exception {
        JsonNode signed = signed();

        String code = validateAndGetCode(validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString()), 200);

        assertThat(code).isEqualTo("VALIDATION.SUCCESS");
    }

    @Test
    void shouldRejectTamperedBundle() throws Exception {
        JsonNode signed = signed();
        String tampered = JadesSigningSystemTest.example("bundle.json").replace("13.50", "13.5");

        assertThat(validateAndGetCode(validationBody(signed.get("signature").toString(), tampered,
                signed.get("provenance").toString()), 422)).isEqualTo("CRYPTO.HASH-VERIFICATION-FAILED");
    }

    @Test
    void shouldAcceptChangeInResourceOutsideProvenanceTargets() throws Exception {
        JsonNode signed = signed();
        String unsignedChanged = JadesSigningSystemTest.example("bundle.json")
                .replace("Laboratório não assinado", "Outro laboratório");

        assertThat(validateAndGetCode(validationBody(signed.get("signature").toString(), unsignedChanged,
                signed.get("provenance").toString()), 200)).isEqualTo("VALIDATION.SUCCESS");
    }

    @Test
    void shouldRejectWhenProvenanceSignatureWasReplaced() throws Exception {
        JsonNode first = signed();
        // RS256 é determinístico: outro iat garante uma assinatura diferente
        JsonNode second = signed(Instant.now().getEpochSecond() - 10);

        assertThat(validateAndGetCode(validationBody(first.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), second.get("provenance").toString()), 422))
                .isEqualTo("VALIDATION.POLICY-COMPLIANCE-FAILED");
    }

    @Test
    void shouldRejectWhenRevocationIsInconclusive() throws Exception {
        JsonNode signed = signed();
        doReturn(RevocationLookup.inconclusive(new RevocationStatus.OcspUnavailable()))
                .when(revocationService).lookup(any(), any());

        assertThat(validateAndGetCode(validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString()), 422))
                .isEqualTo("REVOCATION.OCSP-UNAVAILABLE");
    }

    @Test
    void shouldReturn422WhenTrustStoreIsNotLoaded() throws Exception {
        JsonNode signed = signed();
        doReturn(Optional.empty()).when(trustMaterialSource).current();

        assertThat(validateAndGetCode(validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString()), 422))
                .isEqualTo("CONFIG.TRUST-STORE-EMPTY");
    }

    @Test
    void shouldRejectRequestWithoutSignature() throws Exception {
        String body = "{\"bundle\":" + JadesSigningSystemTest.example("bundle.json")
                + ",\"provenance\":" + JadesSigningSystemTest.example("provenance.json")
                + ",\"referenceTimestamp\":" + Instant.now().getEpochSecond()
                + ",\"policyIdentifierUri\":\"" + JadesSigningSystemTest.POLICY_URI + "\"}";

        assertThat(validateAndGetCode(body, 422)).isEqualTo("FORMAT.SIGNATURE-MISSING");
    }
}
