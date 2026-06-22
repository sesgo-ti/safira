package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.time.Instant;
import java.util.List;

/**
 * Tipo de dado FHIR {@code Signature}, restrito ao perfil de assinatura digital avançada GO SES.
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
