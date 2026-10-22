/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.signing;

import java.util.Objects;

/**
 * Saída da criação de assinatura (caso de uso "criar", saídas 1 e 2): a {@code Signature} FHIR
 * e a nova cópia do {@code Provenance} contendo exatamente essa assinatura, ambas serializadas
 * em JSON sem perda (tokens numéricos e ordem dos membros do Provenance recebido preservados).
 */
public record SigningResult(String signatureJson, String provenanceJson) {

    public SigningResult {
        Objects.requireNonNull(signatureJson, "signatureJson");
        Objects.requireNonNull(provenanceJson, "provenanceJson");
    }
}
