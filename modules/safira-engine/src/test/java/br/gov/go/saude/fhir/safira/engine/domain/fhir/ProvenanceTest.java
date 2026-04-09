package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ProvenanceTest {

    @Test
    void shouldCreateProvenanceFromValidJson() {
        String json = """
                {
                  "resourceType": "Provenance",
                  "id": "prov1",
                  "target": [
                    {"reference": "urn:uuid:p1"},
                    {"reference": "urn:uuid:o1", "type": "Patient", "display": "João"}
                  ]
                }
                """;

        Provenance provenance = Provenance.fromJson(json);

        assertEquals("Provenance", provenance.resourceType());
        assertEquals("prov1", provenance.id());
        assertEquals(2, provenance.target().size());
        assertEquals("urn:uuid:p1", provenance.target().getFirst().reference());
        assertEquals("urn:uuid:o1", provenance.target().get(1).reference());
        assertEquals("Patient", provenance.target().get(1).type());
        assertEquals("João", provenance.target().get(1).display());
        assertEquals(json, provenance.rawJson());
    }

    @Test
    void shouldThrowWhenJsonIsInvalid() {
        assertThrows(IllegalArgumentException.class, () -> Provenance.fromJson("not json"));
    }

    @Test
    void shouldThrowWhenResourceTypeIsNotProvenance() {
        String json = """
                {"resourceType": "Patient", "target": [{"reference": "x"}]}
                """;

        assertThrows(IllegalArgumentException.class, () -> Provenance.fromJson(json));
    }

    @Test
    void shouldThrowWhenTargetIsMissing() {
        String json = """
                {"resourceType": "Provenance"}
                """;

        assertThrows(IllegalArgumentException.class, () -> Provenance.fromJson(json));
    }

    @Test
    void shouldThrowWhenTargetIsEmpty() {
        String json = """
                {"resourceType": "Provenance", "target": []}
                """;

        assertThrows(IllegalArgumentException.class, () -> Provenance.fromJson(json));
    }
}
