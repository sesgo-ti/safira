package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

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

        // Raw provenance in json format
        String rawJson
) {
}
