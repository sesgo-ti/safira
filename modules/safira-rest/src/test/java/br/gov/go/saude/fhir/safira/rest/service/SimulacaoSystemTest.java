/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Sistema no perfil {@code simulacao}: PKI gerada pelo {@link GeradorPkiSimulada}, LCRs locais e
 * nenhum acesso ao acervo do ITI — mesmo pipeline da política 0.2.0, só a confiança muda.
 */
@SpringBootTest
@ActiveProfiles("simulacao")
class SimulacaoSystemTest {

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void simulacao(DynamicPropertyRegistry registry) {
        SimulacaoPki.ambiente().forEach((nome, valor) -> registry.add(nome, () -> valor));
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    private MvcResult enviar(String path, String body) throws Exception {
        return mockMvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(body)).andReturn();
    }

    private JsonNode json(MvcResult result) throws Exception {
        return mapper.readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8));
    }

    private static String code(JsonNode outcome) {
        return outcome.get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
    }

    @Test
    void shouldReportReadinessUpWhenSimulationProfileIsActive() throws Exception {
        MvcResult result = mockMvc.perform(get("/actuator/health/readiness")).andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        assertThat(json(result).get("status").asText()).isEqualTo("UP");
    }

    @Test
    void shouldSignAndValidateWhenSignerIsSimulated() throws Exception {
        MvcResult signed = enviar("/assinar", SimulacaoPki.signingBody(SimulacaoPki.PKI.signatario(),
                GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond()));
        assertThat(signed.getResponse().getStatus()).isEqualTo(200);
        JsonNode response = json(signed);

        MvcResult validated = enviar("/validar", SignAndValidateSystemTest.validationBody(
                response.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                response.get("provenance").toString()));

        assertThat(validated.getResponse().getStatus()).isEqualTo(200);
        assertThat(code(json(validated))).isEqualTo("VALIDATION.SUCCESS");
        assertThat(response.get("signature").get("who").get("identifier").get("value").asText())
                .isEqualTo(GeradorPkiSimulada.CPF_PADRAO);
    }

    @Test
    void shouldRejectSigningWhenSimulatedSignerIsRevoked() throws Exception {
        MvcResult result = enviar("/assinar", SimulacaoPki.signingBody(SimulacaoPki.PKI.revogado(),
                GeradorPkiSimulada.ALIAS_REVOGADO, Instant.now().getEpochSecond()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(code(json(result))).isEqualTo("CERT.REVOKED");
    }
}
