/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

/** Atributos do {@code SigningContext} trocados entre os steps de assinatura da política 0.2.0. */
public final class SigningKeys {

    /** Payload JWS: SHA-256 do artefato enquadrado em base64url sem padding (String). */
    public static final String CONTENT_DIGEST = "contentDigest";
    /** Signing input JWS {@code ASCII(protected '.' payload)} a assinar (byte[]). */
    public static final String SIGNING_INPUT_BYTES = "signingInputBytes";
    /** JWS General JSON Serialization produzido (String). */
    public static final String JWS_FINAL = "jwsFinal";

    private SigningKeys() {
    }
}
