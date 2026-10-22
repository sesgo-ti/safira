/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/** Descumprimento de uma regra da política, com o código do CodeSystem e o diagnóstico. */
public record PolicyViolation(SignatureExceptionCode code, String diagnostics) {
}
