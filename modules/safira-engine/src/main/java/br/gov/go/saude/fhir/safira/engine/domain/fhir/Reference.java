package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

/**
 * Representation of the FHIR Reference data type.
 */
@Builder
public record Reference(
        String reference,
        String type,
        Identifier identifier,
        String display
) {
}
