/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.tsa;

/**
 * Exceção lançada quando a resposta da TSA (Time Stamp Authority) é malformada,
 * indica falha (status diferente de GRANTED/GRANTED_WITH_MODS) ou não passa na
 * validação estrutural conforme RFC 3161.
 */
public class TsaInvalidResponseException extends Exception {

    public TsaInvalidResponseException(String message) {
        super(message);
    }

    public TsaInvalidResponseException(String message, Throwable cause) {
        super(message, cause);
    }
}
