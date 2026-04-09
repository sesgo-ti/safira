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
                targets.add(parseReference(t));
            }

            return new Provenance(resourceType, id, List.copyOf(targets), null, rawJson);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("JSON inválido: " + e.getMessage(), e);
        }
    }

    private static Reference parseReference(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) return null;

        return new Reference(
                node.path("reference").asText(null),
                node.path("type").asText(null),
                parseIdentifier(node.path("identifier")),
                node.path("display").asText(null)
        );
    }

    private static Identifier parseIdentifier(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) return null;

        return new Identifier(
                node.path("use").asText(null),
                parseCoding(node.path("type")),
                node.path("system").asText(null),
                node.path("value").asText(null),
                parseReference(node.path("assigner"))
        );
    }

    private static Coding parseCoding(JsonNode node) {
        if (node.isMissingNode() || node.isNull()) return null;

        return new Coding(
                node.path("system").asText(null),
                node.path("version").asText(null),
                node.path("code").asText(null),
                node.path("display").asText(null),
                node.has("userSelected") ? node.path("userSelected").asBoolean() : null
        );
    }
}
