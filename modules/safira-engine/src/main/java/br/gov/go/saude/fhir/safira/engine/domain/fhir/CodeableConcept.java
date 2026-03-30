package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.util.List;

/**
 * Simplified representation of the FHIR CodeableConcept data type.
 */
@Builder
public record CodeableConcept(
        List<Coding> coding,
        String text
) {
}
