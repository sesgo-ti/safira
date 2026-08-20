/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.jades.JAdESSignatureParameters;

import java.util.Objects;

/**
 * Sessão de assinatura JAdES.
 *
 * <p>Handle opaco que transporta, entre passos do pipeline, os parâmetros DSS e o
 * payload do JWS. A mesma instância de {@link JAdESSignatureParameters} usada em
 * {@code getDataToSign} DEVE ser reutilizada em {@code signDocument} — o DSS deriva
 * o protected header (incluindo {@code iat}) de forma determinística a partir dela.
 *
 * @param parameters parâmetros DSS congelados para esta assinatura
 * @param payload    bytes crus do payload JWS (no perfil SES-GO, os 32 bytes do
 *                   SHA-256 da concatenação das instâncias canonicalizadas)
 */
public record JadesSigningSession(JAdESSignatureParameters parameters, byte[] payload) {

    public JadesSigningSession {
        Objects.requireNonNull(parameters, "parameters não pode ser nulo");
        Objects.requireNonNull(payload, "payload não pode ser nulo");
        payload = payload.clone();
    }

    @Override
    public byte[] payload() {
        return payload.clone();
    }
}
