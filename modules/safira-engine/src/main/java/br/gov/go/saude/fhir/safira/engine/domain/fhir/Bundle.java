package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Simplified representation of a FHIR Bundle restricted to the exact needs
 * of the digital signature process as per Safira's architecture.
 */
@Builder
public record Bundle(
        String resourceType,
        String id,
        List<BundleEntry> entry,
        String rawJson
) {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Bundle fromJson(String rawJson) {
        try {
            JsonNode root = MAPPER.readTree(rawJson);

            String resourceType = root.path("resourceType").asText(null);
            if (!"Bundle".equals(resourceType)) {
                throw new IllegalArgumentException(
                        "resourceType esperado 'Bundle', encontrado: " + resourceType);
            }

            JsonNode entryNode = root.path("entry");
            if (!entryNode.isArray() || entryNode.isEmpty()) {
                throw new IllegalArgumentException(
                        "Bundle deve conter ao menos uma entry.");
            }

            String id = root.path("id").asText(null);

            List<BundleEntry> entries = new ArrayList<>();
            for (JsonNode e : entryNode) {
                entries.add(new BundleEntry(
                        e.path("fullUrl").asText(null),
                        MAPPER.convertValue(e.path("resource"), new TypeReference<>() {})
                ));
            }

            return new Bundle(resourceType, id, List.copyOf(entries), rawJson);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("JSON inválido: " + e.getMessage(), e);
        }
    }

    public Optional<BundleEntry> findEntryByFullUrl(String fullUrl) {
        return entry.stream()
                .filter(e -> e.fullUrl().equals(fullUrl))
                .findFirst();
    }

    @Builder
    public record BundleEntry(
            String fullUrl,
            Map<String, Object> resource
    ) {
    }
}
