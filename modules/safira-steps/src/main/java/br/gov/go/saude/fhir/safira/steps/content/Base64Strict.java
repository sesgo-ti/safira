/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.content;

import java.util.Base64;
import java.util.Optional;

/** Decodificação Base64/Base64URL canônica: rejeita representações alternativas do mesmo valor. */
public final class Base64Strict {

    private Base64Strict() {
    }

    /** Base64 padrão (RFC 4648 §4), com padding canônico e sem espaços. */
    public static Optional<byte[]> standard(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(value);
            return Base64.getEncoder().encodeToString(decoded).equals(value) ? Optional.of(decoded) : Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    /** Base64URL (RFC 4648 §5) sem padding. */
    public static Optional<byte[]> urlNoPadding(String value) {
        if (value == null || value.isEmpty()) {
            return Optional.empty();
        }
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(value);
            return Base64.getUrlEncoder().withoutPadding().encodeToString(decoded).equals(value)
                    ? Optional.of(decoded) : Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
