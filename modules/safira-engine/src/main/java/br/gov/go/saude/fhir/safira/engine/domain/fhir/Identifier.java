package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

/** Tipo de dado FHIR {@code Identifier}. */
@Builder
public record Identifier(
        String use,
        Coding type,
        String system,
        String value,
        Reference assigner
) {
}
