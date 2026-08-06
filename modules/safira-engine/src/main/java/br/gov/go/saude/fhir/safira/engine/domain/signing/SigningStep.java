/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.signing;

import br.gov.go.saude.fhir.safira.engine.domain.Step;

@FunctionalInterface
public interface SigningStep extends Step<SigningContext> {}
