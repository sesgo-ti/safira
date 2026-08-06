/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.mapper;

import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.rest.dto.ValidationInput;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

class ValidationInputMapperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final ValidationInputMapper mapper = new ValidationInputMapper(null);

    @Test
    void shouldMapMinimalInputToContext() {
        ValidationInput input = new ValidationInput(
                "eyJhbGciOiJSUzI1NiJ9..signature",
                1751328000L,
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0",
                null,
                null
        );

        ValidationContext context = mapper.toContext(input);

        assertNotNull(context);
        assertEquals("eyJhbGciOiJSUzI1NiJ9..signature", context.getSignedDataBase64());
        assertEquals(1751328000L, context.getReferenceTimestamp());
        assertEquals("https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0",
                context.getPolicyIdentifierUri());
        assertNull(context.getBundle());
        assertNull(context.getProvenance());
        assertNull(context.getOperationalConfig());
    }

    @Test
    void shouldMapFullInputIncludingBundleAndProvenance() throws Exception {
        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "bundle-1",
                  "entry": [
                    {
                      "fullUrl": "urn:uuid:abc",
                      "resource": {"resourceType": "Patient"}
                    }
                  ]
                }
                """;

        String provenanceJson = """
                {
                  "resourceType": "Provenance",
                  "target": [
                    { "reference": "urn:uuid:abc" }
                  ]
                }
                """;

        ValidationInput input = new ValidationInput(
                "signed-data-base64",
                1760000000L,
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0",
                objectMapper.readTree(bundleJson),
                objectMapper.readTree(provenanceJson)
        );

        ValidationContext context = mapper.toContext(input);

        assertNotNull(context);
        assertEquals("signed-data-base64", context.getSignedDataBase64());
        assertEquals(1760000000L, context.getReferenceTimestamp());
        assertNotNull(context.getBundle());
        assertEquals("Bundle", context.getBundle().resourceType());
        assertEquals("bundle-1", context.getBundle().id());
        assertEquals(1, context.getBundle().entry().size());
        assertNotNull(context.getProvenance());
        assertEquals("Provenance", context.getProvenance().resourceType());
        assertEquals(1, context.getProvenance().target().size());
        assertEquals("urn:uuid:abc", context.getProvenance().target().get(0).reference());
    }
}
