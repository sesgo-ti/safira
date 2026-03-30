package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.time.Instant;
import java.util.List;

/**
 * Representation of the FHIR Signature data type, optimized for the "Assinatura digital avançada" profile.
 * Standard FHIR attributes are respected.
 */
@Builder
public record Signature(
        List<Coding> type,
        Instant when,
        Reference who,
        Reference onBehalfOf,
        String targetFormat,
        String sigFormat,
        byte[] data
) {
}
