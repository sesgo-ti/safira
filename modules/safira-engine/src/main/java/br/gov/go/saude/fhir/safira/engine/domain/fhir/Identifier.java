package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

/**
 * Representation of the FHIR Identifier data type.
 */
@Builder
public record Identifier(
        String use,
        Coding type,
        String system,
        String value,
        Reference assigner
) {
}
