package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

/** Tipo de dado FHIR {@code Reference}. */
@Builder
public record Reference(
        String reference,
        String type,
        Identifier identifier,
        String display
) {
}
