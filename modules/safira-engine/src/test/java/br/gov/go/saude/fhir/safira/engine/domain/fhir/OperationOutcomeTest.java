/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class OperationOutcomeTest {

    @Test
    void shouldOmitNullMembersWhenSerialized() throws Exception {
        OperationOutcome outcome = OperationOutcome.createSignatureError("error", "processing",
                "CERT.REVOKED", "Certificado revogado", null);

        String json = new ObjectMapper().writeValueAsString(outcome);

        assertThat(json).doesNotContain("null").doesNotContain("\"id\"").doesNotContain("\"location\"")
                .doesNotContain("\"diagnostics\"").doesNotContain("\"version\"").doesNotContain("\"display\"");
        assertThat(json).contains("\"code\":\"CERT.REVOKED\"").contains("\"text\":\"Certificado revogado\"");
    }

    @Test
    void shouldOmitNullMembersOfCodeableConceptWithoutText() throws Exception {
        CodeableConcept concept = CodeableConcept.builder().coding(List.of(Coding.builder().code("x").build())).build();

        assertThat(new ObjectMapper().writeValueAsString(concept)).isEqualTo("{\"coding\":[{\"code\":\"x\"}]}");
    }
}
