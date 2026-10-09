/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.rest.service.SignAndValidateSystemTest;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Aviso de simulação com o DispatcherServlet sob prefixo ({@code spring.mvc.servlet.path=/api}): o
 * sucesso de {@code /api/validar} continua marcado — o aviso não pode falhar aberto por causa do caminho.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "spring.mvc.servlet.path=/api")
@ActiveProfiles("simulacao")
class SimulacaoPrefixoServletSystemTest {

    @LocalServerPort
    int porta;

    private final HttpClient http = HttpClient.newHttpClient();
    private final ObjectMapper mapper = new ObjectMapper();

    @DynamicPropertySource
    static void simulacao(DynamicPropertyRegistry registry) {
        SimulacaoPki.ambiente().forEach((nome, valor) -> registry.add(nome, () -> valor));
    }

    private HttpResponse<String> enviar(String caminho, String corpo) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + porta + caminho))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(corpo, StandardCharsets.UTF_8))
                .build();
        return http.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
    }

    @Test
    void shouldFlagSimulationWhenValidationSucceedsUnderServletPrefix() throws Exception {
        HttpResponse<String> assinada = enviar("/api/assinar", SimulacaoPki.signingBody(SimulacaoPki.PKI.signatario(),
                GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond()));
        assertThat(assinada.statusCode()).isEqualTo(200);
        JsonNode resposta = mapper.readTree(assinada.body());

        HttpResponse<String> validada = enviar("/api/validar", SignAndValidateSystemTest.validationBody(
                resposta.get("signature").toString(), JadesSigningSystemTest.example("bundle.json"),
                resposta.get("provenance").toString()));

        assertThat(validada.statusCode()).isEqualTo(200);
        assertThat(validada.body()).contains(AvisoSimulacaoAdvice.TEXTO);
    }
}
