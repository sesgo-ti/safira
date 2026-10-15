/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

/** Tipo de dado FHIR {@code Coding}. */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record Coding(
        String system,
        String version,
        String code,
        String display,
        Boolean userSelected
) {
}
