/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
class SignatureControllerValidationTest {

    private static final String VALID_POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";
    private static final long VALID_REFERENCE_TS = 1760000000L;

    @Autowired
    private WebApplicationContext webApplicationContext;

    private MockMvc mockMvc;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        this.mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).build();
    }

    @Test
    void shouldReturn400WhenSignedDataBase64IsBlank() throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("signedDataBase64", "");
        body.put("referenceTimestamp", VALID_REFERENCE_TS);
        body.put("policyIdentifierUri", VALID_POLICY_URI);

        mockMvc.perform(post("/validar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body.toString()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldReturn400WhenReferenceTimestampOutOfRange() throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("signedDataBase64", "eyJhbGciOiJSUzI1NiJ9..signature");
        body.put("referenceTimestamp", 100L);
        body.put("policyIdentifierUri", VALID_POLICY_URI);

        mockMvc.perform(post("/validar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body.toString()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldReturn400WhenPolicyIdentifierUriInvalid() throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("signedDataBase64", "eyJhbGciOiJSUzI1NiJ9..signature");
        body.put("referenceTimestamp", VALID_REFERENCE_TS);
        body.put("policyIdentifierUri", "not-a-valid-uri");

        mockMvc.perform(post("/validar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body.toString()))
                .andExpect(status().isBadRequest());
    }

    @Test
    void shouldReturn422WhenJwsIsMalformed() throws Exception {
        ObjectNode body = objectMapper.createObjectNode();
        body.put("signedDataBase64", "bm90LWEtandz");
        body.put("referenceTimestamp", VALID_REFERENCE_TS);
        body.put("policyIdentifierUri", VALID_POLICY_URI);

        mockMvc.perform(post("/validar")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body.toString()))
                .andExpect(status().isUnprocessableEntity())
                .andExpect(content().contentTypeCompatibleWith("application/fhir+json"))
                .andExpect(jsonPath("$.resourceType").value("OperationOutcome"))
                .andExpect(jsonPath("$.issue").isArray());
    }

    @Test
    @Disabled("TODO: add E2E happy-path once fixture generation from SigningService is available")
    void shouldReturn200WhenSignatureIsValid() {
        // Placeholder for future end-to-end happy path test
    }
}
