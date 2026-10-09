/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SignAndValidateSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SigningService;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Segurança do modo simulação: a assinatura produzida com a PKI simulada é recusada por um Safira
 * em modo normal, cujo acervo ({@link ModoIcpBrasilDeTeste}: outra raiz no lugar das raízes
 * ICP-Brasil) não contém a raiz simulada — mesmo com a allowlist apontando para a AC simulada.
 */
@SpringBootTest(properties = "safira.simulacao.enabled=false")
@Import(ModoIcpBrasilDeTeste.class)
class SimulacaoForaDoModoSystemTest {

    static SigningResult assinaturaSimulada;

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        registry.add("safira.policy.accepted-certificate-policies[0].oid", SimulacaoPki.PKI::politicaOid);
        registry.add("safira.policy.accepted-certificate-policies[0].type", () -> "A3");
        registry.add("safira.policy.accepted-certificate-policies[0].issuer-sha256", SimulacaoPki.PKI::issuerSha256);
    }

    /** Assina num Safira à parte, no modo simulação. */
    @BeforeAll
    static void assinarEmModoSimulacao() throws Exception {
        String[] propriedades = SimulacaoPki.ambiente().entrySet().stream()
                .map(entrada -> entrada.getKey() + "=" + entrada.getValue())
                .toArray(String[]::new);
        try (ConfigurableApplicationContext simulacao = new SpringApplicationBuilder(SimuladorTestApplication.class)
                .web(WebApplicationType.NONE)
                .properties(propriedades)
                .run()) {
            PipelineResult<?> result = simulacao.getBean(SigningService.class).sign(SimulacaoPki.signingBody(
                    SimulacaoPki.PKI.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond()));
            assinaturaSimulada = (SigningResult) ((PipelineResult.Success<?>) result).getValue();
        }
    }

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void shouldRejectSimulatedSignatureWhenSimulationModeIsOff() throws Exception {
        String body = SignAndValidateSystemTest.validationBody(assinaturaSimulada.signatureJson(),
                JadesSigningSystemTest.example("bundle.json"), assinaturaSimulada.provenanceJson());

        MvcResult result = mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content(body))
                .andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(new ObjectMapper().readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("issue").get(0).get("details").get("coding").get(0).get("code").asText())
                .isEqualTo("CERT.NOT-ICP-BRASIL");
    }
}
