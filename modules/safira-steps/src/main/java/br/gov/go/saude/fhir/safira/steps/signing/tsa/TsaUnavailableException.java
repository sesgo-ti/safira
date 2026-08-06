/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.tsa;

/**
 * Exceção lançada quando a TSA (Time Stamp Authority) não responde dentro do timeout
 * configurado ou há falha de rede ao tentar obter um carimbo de tempo.
 */
public class TsaUnavailableException extends Exception {

    public TsaUnavailableException(String message) {
        super(message);
    }

    public TsaUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
