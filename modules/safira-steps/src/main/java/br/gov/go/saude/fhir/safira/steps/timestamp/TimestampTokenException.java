/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.timestamp;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/** {@code TimeStampToken} ausente, ilegível ou estruturalmente inválido. */
public class TimestampTokenException extends RuntimeException {

    private final SignatureExceptionCode code;

    public TimestampTokenException(SignatureExceptionCode code, String message) {
        super(message);
        this.code = code;
    }

    public TimestampTokenException(SignatureExceptionCode code, String message, Throwable cause) {
        super(message, cause);
        this.code = code;
    }

    public SignatureExceptionCode getCode() {
        return code;
    }
}
