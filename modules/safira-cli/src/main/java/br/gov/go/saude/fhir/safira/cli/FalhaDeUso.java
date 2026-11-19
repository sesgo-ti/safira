/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;

/**
 * Erro de uso ou de entrada (saída 3). Com {@code outcome}, o {@code OperationOutcome} vai para o
 * stdout; a mensagem vai sempre para o stderr.
 */
final class FalhaDeUso extends RuntimeException {

    private final transient OperationOutcome outcome;

    FalhaDeUso(String mensagem) {
        this(mensagem, null);
    }

    FalhaDeUso(String mensagem, OperationOutcome outcome) {
        super(mensagem);
        this.outcome = outcome;
    }

    OperationOutcome outcome() {
        return outcome;
    }
}
