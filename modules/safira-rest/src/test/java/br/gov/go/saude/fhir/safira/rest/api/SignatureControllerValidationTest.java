/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.api;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.time.Instant;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** Contrato HTTP de {@code /validar} e {@code /versoes} para entradas inválidas (política 0.2.0). */
@SpringBootTest
class SignatureControllerValidationTest {

    private static final String POLICY_URI = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";
    private static final String CODE = "$.issue[0].details.coding[0].code";

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    private static String body(String policyUri, long referenceTimestamp) {
        return "{\"signature\":{\"data\":\"eA==\"},\"bundle\":{\"resourceType\":\"Bundle\"},"
                + "\"provenance\":{\"resourceType\":\"Provenance\"},\"referenceTimestamp\":" + referenceTimestamp
                + ",\"policyIdentifierUri\":\"" + policyUri + "\"}";
    }

    @Test
    void shouldReturn422WhenSignatureIsMissing() throws Exception {
        mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"bundle\":{},\"provenance\":{},\"referenceTimestamp\":" + Instant.now().getEpochSecond()
                                + ",\"policyIdentifierUri\":\"" + POLICY_URI + "\"}"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().contentTypeCompatibleWith("application/fhir+json"))
                .andExpect(jsonPath(CODE).value("FORMAT.SIGNATURE-MISSING"));
    }

    @Test
    void shouldReturn422WhenReferenceTimestampOutOfRange() throws Exception {
        mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content(body(POLICY_URI, 1000L)))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath(CODE).value("FORMAT.INVALID-TIMESTAMP"));
    }

    @Test
    void shouldReturn422WhenPolicyIdentifierUriInvalid() throws Exception {
        mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON)
                        .content(body("not-a-valid-uri", Instant.now().getEpochSecond())))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath(CODE).value("POLICY.URI-INVALID"));
    }

    @Test
    void shouldReturn422WhenBodyIsNotJson() throws Exception {
        mockMvc.perform(post("/validar").contentType(MediaType.APPLICATION_JSON).content("não é json"))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(jsonPath(CODE).value("FORMAT.BUNDLE-MALFORMED"));
    }

    @Test
    void shouldListOnlyPolicy020() throws Exception {
        mockMvc.perform(get("/versoes"))
                .andExpect(status().isOk())
                .andExpect(content().string("[" + POLICY_URI + "]"));
    }
}
