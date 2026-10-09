/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Modo simulação com PKI em arquivos (sem TSA em memória): a estratégia {@code tsa} falha com
 * {@code TSA.UNAVAILABLE} sem abrir conexão alguma, mesmo com {@code tsa-url} apontando para um
 * servidor local que aceitaria a conexão.
 */
@ActiveProfiles("simulador")
@SpringBootTest
class SimulacaoTsaSemRedeSystemTest {

    static final AtomicInteger CONEXOES = new AtomicInteger();
    static final ServerSocket TSA = escutar();

    @Autowired
    WebApplicationContext webApplicationContext;

    @DynamicPropertySource
    static void simulacao(DynamicPropertyRegistry registry) {
        SimulacaoPki.ambiente().forEach((nome, valor) -> registry.add(nome, () -> valor));
        registry.add("safira.operational.verification.tsa-url", () -> "https://127.0.0.1:" + TSA.getLocalPort() + "/tsa");
        registry.add("safira.policy.tsa-policies.version", () -> "1.0.0");
        registry.add("safira.policy.tsa-policies.policies[0].oid", () -> PkiIcpSimulada.POLITICA_TSA);
        registry.add("safira.policy.tsa-policies.policies[0].max-accuracy-seconds", () -> "1");
        registry.add("safira.policy.tsa-policies.policies[0].trust-store.reference",
                () -> SimulacaoPki.PKI.raiz().toUri().toString());
    }

    private static ServerSocket escutar() {
        try {
            ServerSocket servidor = new ServerSocket(0);
            Thread.ofVirtual().start(() -> {
                while (!servidor.isClosed()) {
                    try (Socket ignorada = servidor.accept()) {
                        CONEXOES.incrementAndGet();
                    } catch (IOException encerrado) {
                        // socket fechado ao fim do teste
                    }
                }
            });
            return servidor;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @AfterAll
    static void encerrar() throws IOException {
        TSA.close();
    }

    @Test
    void shouldFailWithTsaUnavailableWithoutConnectingWhenPkiIsLoadedFromFiles() throws Exception {
        String corpo = SimulacaoPki.signingBody(SimulacaoPki.PKI, SimulacaoPki.PKI.signatario(),
                GeradorPkiSimulada.ALIAS_SIGNATARIO, Instant.now().getEpochSecond(), "tsa");

        MvcResult result = MockMvcBuilders.webAppContextSetup(webApplicationContext).build()
                .perform(post("/assinar").contentType(MediaType.APPLICATION_JSON).content(corpo)).andReturn();

        assertThat(result.getResponse().getStatus()).isEqualTo(422);
        assertThat(new ObjectMapper().readTree(result.getResponse().getContentAsString(StandardCharsets.UTF_8))
                .get("issue").get(0).get("details").get("coding").get(0).get("code").asText())
                .isEqualTo("TSA.UNAVAILABLE");
        assertThat(CONEXOES.get()).isZero();
    }
}
