package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

/**
 * Representation of the FHIR Coding data type.
 */
@Builder
public record Coding(
        String system,
        String version,
        String code,
        String display,
        Boolean userSelected
) {
}
