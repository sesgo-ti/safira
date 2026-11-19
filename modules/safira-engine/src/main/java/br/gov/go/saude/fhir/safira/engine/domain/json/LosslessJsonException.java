/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.json;

/** JSON inválido, ambíguo (membro duplicado) ou com Unicode inválido. */
public class LosslessJsonException extends RuntimeException {

    public LosslessJsonException(String message) {
        super(message);
    }

    public LosslessJsonException(String message, Throwable cause) {
        super(message, cause);
    }
}
