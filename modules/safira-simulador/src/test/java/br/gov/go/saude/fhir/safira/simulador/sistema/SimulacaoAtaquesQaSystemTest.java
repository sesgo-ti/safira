/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SignAndValidateSystemTest;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
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
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * QA adversarial no perfil {@code simulacao}: confiança cruzada com outra PKI e distinção entre
 * artefatos simulados e reais. Testes {@code @Disabled("VULN-Sn")} documentam vulnerabilidades.
 */
@SpringBootTest
@ActiveProfiles("simulacao")
class SimulacaoAtaquesQaSystemTest {

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

    private JsonNode assinarSimulado() throws Exception {
        MvcResult signed = enviar("/assinar", SimulacaoPki.signingBody(SimulacaoPki.PKI.signatario(),
                GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond()));
        assertThat(signed.getResponse().getStatus()).isEqualTo(200);
        return json(signed);
    }

    @Test
    void shouldRejectSignerFromAnotherPkiWhenSimulationIsOn() throws Exception {
        MvcResult result = enviar("/assinar", JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI,
                Instant.now().getEpochSecond()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldRejectTamperedSimulatedSignatureWhenValidatingInSimulation() throws Exception {
        String bundle = JadesSigningSystemTest.example("bundle.json");
        JsonNode simulada = assinarSimulado();
        ObjectNode signature = (ObjectNode) simulada.get("signature").deepCopy();
        ObjectNode jws = (ObjectNode) mapper.readTree(Base64.getDecoder().decode(signature.get("data").asText()));
        ObjectNode alvo = jws.has("signatures") ? (ObjectNode) jws.get("signatures").get(0) : jws;
        String assinatura = alvo.get("signature").asText();
        alvo.put("signature", (assinatura.startsWith("A") ? "B" : "A") + assinatura.substring(1));
        signature.put("data", Base64.getEncoder().encodeToString(jws.toString().getBytes(StandardCharsets.UTF_8)));

        MvcResult result = enviar("/validar", SignAndValidateSystemTest.validationBody(signature.toString(), bundle,
                simulada.get("provenance").toString()));

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
    }

    @Test
    void shouldFlagSimulationWhenValidationSucceedsInSimulationMode() throws Exception {
        JsonNode simulada = assinarSimulado();

        MvcResult validated = enviar("/validar", SignAndValidateSystemTest.validationBody(
                simulada.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                simulada.get("provenance").toString()));

        assertThat(validated.getResponse().getStatus()).isEqualTo(200);
        assertThat(validated.getResponse().getContentAsString(StandardCharsets.UTF_8).toUpperCase())
                .contains("SIMULA");
    }

    @Test
    @Disabled("VULN-S7 pendente de decisão do responsável: assinatura simulada usa a mesma política (sigPId) e o mesmo Signature FHIR da real")
    void shouldMarkSimulatedSignatureOutsideCertificateWhenSigning() throws Exception {
        JsonNode simulada = assinarSimulado();
        ObjectNode signature = (ObjectNode) simulada.get("signature").deepCopy();
        JsonNode jws = mapper.readTree(Base64.getDecoder().decode(signature.remove("data").asText()));
        JsonNode alvo = jws.has("signatures") ? jws.get("signatures").get(0) : jws;
        ObjectNode header = (ObjectNode) mapper.readTree(Base64.getUrlDecoder().decode(alvo.get("protected").asText()));
        header.remove("x5c");

        assertThat((header + signature.toString()).toUpperCase()).contains("SIMULA");
    }
}
