/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
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

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * QA adversarial de {@code POST /validar} no nível HTTP: envelope da requisição (membros
 * duplicados, aninhamento extremo, tipos trocados) sobre um artefato legítimo de {@code /assinar}.
 */
@SpringBootTest
@Import(OfflineRevocationConfig.class)
class QaValidacaoRestAtaquesTest {

    @MockitoBean
    FonteDeConfianca fonteDeConfianca;

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
        when(fonteDeConfianca.atual()).thenReturn(AcervoDeTeste.com(JadesSigningSystemTest.PKI.raiz(), JadesSigningSystemTest.PKI.ac()));
        OfflineRevocationConfig.reset();
    }

    private JsonNode signed() throws Exception {
        String body = JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI, Instant.now().getEpochSecond());
        MvcResult result = mockMvc.perform(post("/assinar").contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private MvcResult validate(String body) throws Exception {
        return mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    private String code(MvcResult result) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    @Test
    void shouldAcceptLegitimateArtifactAsControl() throws Exception {
        JsonNode signed = signed();

        MvcResult result = validate(SignAndValidateSystemTest.validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString()));

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(code(result)).isEqualTo("VALIDATION.SUCCESS");
    }

    @Test
    void shouldRejectRequestWhenBundleMemberIsDuplicatedWithTamperedCopy() throws Exception {
        JsonNode signed = signed();
        String bundle = JadesSigningSystemTest.example("bundle.json");
        String body = SignAndValidateSystemTest.validationBody(signed.get("signature").toString(), bundle,
                signed.get("provenance").toString());
        String duplicated = body.replaceFirst("\"bundle\":", "\"bundle\":" + bundle.replace("13.50", "99.99") + ",\"bundle\":");

        MvcResult result = validate(duplicated);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }

    @Test
    void shouldRejectRequestWhenProvenanceSignatureHasDuplicateMember() throws Exception {
        JsonNode signed = signed();
        String provenance = signed.get("provenance").toString()
                .replaceFirst("\"sigFormat\":", "\"sigFormat\":\"text/plain\",\"sigFormat\":");

        MvcResult result = validate(SignAndValidateSystemTest.validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), provenance));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }

    @Test
    void shouldRejectDeeplyNestedRequestWithoutServerError() throws Exception {
        String nested = "[".repeat(200_000) + "]".repeat(200_000);
        String body = "{\"signature\":" + nested + "}";

        MvcResult result = validate(body);

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }

    @Test
    void shouldRejectSignatureWhenSentAsStringInsteadOfObject() throws Exception {
        JsonNode signed = signed();
        String asString = mapper.writeValueAsString(signed.get("signature").toString());

        MvcResult result = validate(SignAndValidateSystemTest.validationBody(asString,
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.SIGNATURE-MISSING");
    }

    @Test
    void shouldRejectRequestWhenReferenceTimestampIsFarInFuture() throws Exception {
        JsonNode signed = signed();

        MvcResult result = validate(SignAndValidateSystemTest.validationBody(signed.get("signature").toString(),
                JadesSigningSystemTest.example("bundle.json"), signed.get("provenance").toString(),
                Instant.now().getEpochSecond() + 3600));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(result)).isEqualTo("FORMAT.INVALID-TIMESTAMP");
    }
}
