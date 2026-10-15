/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.simulador;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * Sistema: {@code POST /assinar} seguido de {@code POST /validar} com o profile
 * {@code simulado} ativo, nenhum mock manual aqui, é exatamente o que um desenvolvedor
 * roda localmente (ver {@code docs/simulacao-sem-certificado-real.md}). Existe para que a
 * build quebre se o simulador em si quebrar: não cobre os comandos `jq`/`curl` documentados,
 * que não são exercitados por este teste.
 */
@SpringBootTest
@ActiveProfiles("simulado")
class SimuladorProfileSystemTest {

    private static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";

    @Autowired
    SimuladorPki pki;

    @Autowired
    WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;
    private final ObjectMapper mapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void shouldSignAndValidateUsingGeneratedPki() throws Exception {
        String bundle = example("bundle.json");
        String provenance = example("provenance.json");
        long referenceTimestamp = Instant.now().getEpochSecond();

        String signingBody = "{\"bundle\":" + bundle
                + ",\"provenance\":" + provenance
                + ",\"signerCryptoMaterial\":{\"type\":\"PEM\",\"privateKeyBase64\":\""
                + Base64.getEncoder().encodeToString(pki.leafKeyPem().getBytes(StandardCharsets.UTF_8)) + "\"}"
                + ",\"certificateChain\":[\"" + Base64.getEncoder().encodeToString(pemToDer(pki.leafCertPem())) + "\"]"
                + ",\"referenceTimestamp\":" + referenceTimestamp
                + ",\"strategy\":\"iat\""
                + ",\"policyIdentifierUri\":\"" + POLICY_URI + "\"}";

        MvcResult signed = mockMvc.perform(post("/assinar")
                        .contentType(MediaType.APPLICATION_JSON).content(signingBody))
                .andReturn();
        assertThat(signed.getResponse().getStatus()).isEqualTo(200);

        JsonNode signedJson = mapper.readTree(signed.getResponse().getContentAsString(StandardCharsets.UTF_8));

        String validationBody = "{\"signature\":" + signedJson.get("signature")
                + ",\"bundle\":" + bundle
                + ",\"provenance\":" + signedJson.get("provenance")
                + ",\"referenceTimestamp\":" + Instant.now().getEpochSecond()
                + ",\"policyIdentifierUri\":\"" + POLICY_URI + "\"}";

        MvcResult validated = mockMvc.perform(post("/validar")
                        .contentType(MediaType.APPLICATION_JSON).content(validationBody))
                .andReturn();
        assertThat(validated.getResponse().getStatus()).isEqualTo(200);

        JsonNode outcome = mapper.readTree(validated.getResponse().getContentAsString(StandardCharsets.UTF_8));
        String code = outcome.get("issue").get(0).get("details").get("coding").get(0).get("code").asText();
        assertThat(code).isEqualTo("VALIDATION.SUCCESS");
    }

    private static byte[] pemToDer(String pem) {
        String base64 = pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    private static String example(String name) throws Exception {
        return Files.readString(Path.of("src/test/resources/examples/politica-0.2.0/" + name), StandardCharsets.UTF_8);
    }
}
