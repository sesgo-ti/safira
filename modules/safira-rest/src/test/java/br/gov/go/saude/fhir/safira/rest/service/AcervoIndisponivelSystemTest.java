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
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/** Sistema com a porta de confiança vazia: falha fechado (422, nunca 500) e readiness DOWN. */
@SpringBootTest
@Import(OfflineRevocationConfig.class)
class AcervoIndisponivelSystemTest {

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
        when(fonteDeConfianca.atual()).thenReturn(Optional.empty());
        OfflineRevocationConfig.reset();
    }

    private JsonNode json(MvcResult result) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static String code(JsonNode outcome) {
        return outcome.get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    private MvcResult enviar(String path, String body) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    @Test
    void shouldReturn422TrustStoreEmptyWhenSigningWithoutCatalog() throws Exception {
        MvcResult result = enviar("/assinar",
                JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI, Instant.now().getEpochSecond()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(json(result))).isEqualTo("CONFIG.TRUST-STORE-EMPTY");
    }

    @Test
    void shouldReturn422TrustStoreEmptyWhenValidatingWithoutCatalog() throws Exception {
        when(fonteDeConfianca.atual())
                .thenReturn(AcervoDeTeste.com(JadesSigningSystemTest.PKI.caCert));
        JsonNode signed = json(enviar("/assinar", JadesSigningSystemTest.signingBody(
                JadesSigningSystemTest.POLICY_URI, Instant.now().getEpochSecond())));
        when(fonteDeConfianca.atual()).thenReturn(Optional.empty());

        MvcResult result = enviar("/validar", SignAndValidateSystemTest.validationBody(
                signed.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                signed.get("provenance").toString()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(json(result))).isEqualTo("CONFIG.TRUST-STORE-EMPTY");
    }

    @Test
    void shouldReportReadinessDownWhenCatalogIsUnavailable() throws Exception {
        MvcResult result = mockMvc.perform(get("/actuator/health/readiness")).andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(503);
        assertThat(json(result).get("status").asText()).isEqualTo("DOWN");
    }
}
