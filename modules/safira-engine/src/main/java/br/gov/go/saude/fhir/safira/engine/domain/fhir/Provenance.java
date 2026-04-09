package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;

import java.util.ArrayList;
import java.util.List;

/**
 * Simplified representation of a FHIR Provenance restricted to the exact needs
 * of the digital signature process as per Safira's architecture.
 */
@Builder
public record Provenance(
        String resourceType,
        String id,
        List<Reference> target,
        List<Signature> signature,
        String rawJson
) {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Provenance fromJson(String rawJson) {
        try {
            JsonNode root = MAPPER.readTree(rawJson);

            String resourceType = root.path("resourceType").asText(null);
            if (!"Provenance".equals(resourceType)) {
                throw new IllegalArgumentException(
                        "resourceType esperado 'Provenance', encontrado: " + resourceType);
            }

            JsonNode targetNode = root.path("target");
            if (!targetNode.isArray() || targetNode.isEmpty()) {
                throw new IllegalArgumentException(
                        "Provenance deve conter ao menos um target.");
            }

            String id = root.path("id").asText(null);

            List<Reference> targets = new ArrayList<>();
            for (JsonNode t : targetNode) {
                targets.add(new Reference(
                        t.path("reference").asText(null),
                        t.path("type").asText(null),
                        null,
                        t.path("display").asText(null)
                ));
            }

            return new Provenance(resourceType, id, List.copyOf(targets), null, rawJson);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("JSON inválido: " + e.getMessage(), e);
        }
    }
}
