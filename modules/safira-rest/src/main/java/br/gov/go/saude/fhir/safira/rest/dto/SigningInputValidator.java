/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.dto;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import java.time.Instant;

@Component
public class SigningInputValidator implements Validator {

    private static final long MAX_TIME_DRIFT_SECONDS = 300; // ±5 minutes

    @Override
    public boolean supports(Class<?> clazz) {
        return SigningInput.class.isAssignableFrom(clazz);
    }

    @Override
    public void validate(Object target, Errors errors) {
        SigningInput input = (SigningInput) target;

        if (input.referenceTimestamp() != null) {
            long currentServerTime = Instant.now().getEpochSecond();
            long timeDiff = Math.abs(currentServerTime - input.referenceTimestamp());
            
            if (timeDiff > MAX_TIME_DRIFT_SECONDS) {
                errors.rejectValue(
                        "referenceTimestamp",
                        "timestamp.outofsync",
                        "O timestamp de referência fornecido excede a tolerância de ±5 minutos em relação ao relógio do servidor UTC."
                );
            }
        }
    }
}
