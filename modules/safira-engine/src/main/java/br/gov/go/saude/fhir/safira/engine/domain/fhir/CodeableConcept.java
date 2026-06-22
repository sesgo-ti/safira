package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.util.List;

/** Tipo de dado FHIR {@code CodeableConcept}. */
@Builder
public record CodeableConcept(
        List<Coding> coding,
        String text
) {
}
