package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.util.List;
import java.util.Map;

/**
 * Simplified representation of a FHIR Bundle restricted to the exact needs
 * of the digital signature process as per Safira's architecture.
 */
@Builder
public record Bundle(
        String resourceType,
        String id,
        List<BundleEntry> entry,

        // Raw bundle in json format
        String rawJson
) {
    @Builder
    public record BundleEntry(
            String fullUrl,
            Map<String, Object> resource
    ) {
    }
}
