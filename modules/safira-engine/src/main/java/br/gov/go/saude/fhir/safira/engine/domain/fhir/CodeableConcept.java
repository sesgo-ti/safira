/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.util.List;

/** Tipo de dado FHIR {@code CodeableConcept}. */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record CodeableConcept(
        List<Coding> coding,
        String text
) {
}
