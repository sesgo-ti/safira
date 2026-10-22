/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.request;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/** Requisição que não pode ser convertida em contexto de pipeline; mapeada para 422 com o código. */
public class RequestParsingException extends RuntimeException {

    private final SignatureExceptionCode code;

    public RequestParsingException(SignatureExceptionCode code, String message) {
        super(message);
        this.code = code;
    }

    public SignatureExceptionCode getCode() {
        return code;
    }
}
