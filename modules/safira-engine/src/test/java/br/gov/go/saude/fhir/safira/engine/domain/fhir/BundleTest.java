/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class BundleTest {

    @Test
    void shouldCreateBundleFromValidJson() {
        String json = """
                {
                  "resourceType": "Bundle",
                  "id": "b1",
                  "entry": [
                    {
                      "fullUrl": "urn:uuid:p1",
                      "resource": {"resourceType": "Patient", "name": "João"}
                    }
                  ]
                }
                """;

        Bundle bundle = Bundle.fromJson(json);

        assertEquals("Bundle", bundle.resourceType());
        assertEquals("b1", bundle.id());
        assertEquals(1, bundle.entry().size());
        assertEquals("urn:uuid:p1", bundle.entry().getFirst().fullUrl());
        assertTrue(bundle.entry().getFirst().resource().contains("\"resourceType\":\"Patient\""));
        assertEquals(json, bundle.rawJson());
    }

    @Test
    void shouldCreateBundleWithMultipleEntries() {
        String json = """
                {
                  "resourceType": "Bundle",
                  "entry": [
                    {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient"}},
                    {"fullUrl": "urn:uuid:o1", "resource": {"resourceType": "Observation"}}
                  ]
                }
                """;

        Bundle bundle = Bundle.fromJson(json);

        assertEquals(2, bundle.entry().size());
        assertEquals("urn:uuid:o1", bundle.entry().get(1).fullUrl());
    }

    @Test
    void shouldPreserveDecimalPrecisionInResource() {
        String json = """
                {
                  "resourceType": "Bundle",
                  "entry": [{
                    "fullUrl": "urn:uuid:o1",
                    "resource": {"resourceType": "Observation", "valueQuantity": {"value": 1.0}}
                  }]
                }
                """;

        Bundle bundle = Bundle.fromJson(json);

        assertTrue(bundle.entry().getFirst().resource().contains("1.0"));
    }

    @Test
    void shouldThrowWhenJsonIsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> Bundle.fromJson("{ invalid }"));
    }

    @Test
    void shouldThrowWhenResourceTypeIsNotBundle() {
        String json = """
                {"resourceType": "Patient", "entry": [{"fullUrl": "x", "resource": {}}]}
                """;

        assertThrows(IllegalArgumentException.class, () -> Bundle.fromJson(json));
    }

    @Test
    void shouldThrowWhenEntryIsMissing() {
        String json = """
                {"resourceType": "Bundle"}
                """;

        assertThrows(IllegalArgumentException.class, () -> Bundle.fromJson(json));
    }

    @Test
    void shouldThrowWhenEntryIsEmpty() {
        String json = """
                {"resourceType": "Bundle", "entry": []}
                """;

        assertThrows(IllegalArgumentException.class, () -> Bundle.fromJson(json));
    }

    @Test
    void shouldPreserveFindEntryByFullUrl() {
        String json = """
                {
                  "resourceType": "Bundle",
                  "entry": [
                    {"fullUrl": "urn:uuid:p1", "resource": {"resourceType": "Patient"}}
                  ]
                }
                """;

        Bundle bundle = Bundle.fromJson(json);

        assertTrue(bundle.findEntryByFullUrl("urn:uuid:p1").isPresent());
        assertTrue(bundle.findEntryByFullUrl("urn:uuid:nao-existe").isEmpty());
    }
}
