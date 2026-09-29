/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

/** Atributos do {@code ValidationContext} trocados entre os steps de validação da política 0.2.0. */
public final class ValidationKeys {

    /** JWS General JSON decodificado de {@code Signature.data} (String). */
    public static final String JWS_JSON = "jwsJson";
    /** Nível JAdES local identificado ({@link JadesLevel}). */
    public static final String JADES_LEVEL = "jadesLevel";
    /** {@code iat} do protected header (Long, epoch seconds). */
    public static final String IAT = "iat";
    /** Bytes decodificados do payload attached (32 bytes). */
    public static final String PAYLOAD = "payload";
    /** Texto exato de {@code signatures[0].signature}. */
    public static final String SIGNATURE_TEXT = "signatureText";
    /** Identidade do titular extraída do certificado ({@code SignerIdentity}). */
    public static final String SIGNER_IDENTITY = "signerIdentity";

    private ValidationKeys() {
    }
}
