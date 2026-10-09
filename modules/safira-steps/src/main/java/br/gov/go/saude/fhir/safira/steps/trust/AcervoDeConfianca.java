/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Snapshot imutável de uma geração do acervo de confiança.
 *
 * @param geracao        identificador da geração; muda quando o acervo muda
 * @param raizes         âncoras confiáveis (ao menos uma)
 * @param intermediarias pool NÃO confiável de ACs intermediárias, usado só para montar a
 *                       cadeia; o DSS revalida cada uma até uma raiz confiável
 */
public record AcervoDeConfianca(String geracao, List<X509Certificate> raizes, List<X509Certificate> intermediarias) {

    public AcervoDeConfianca {
        Objects.requireNonNull(geracao, "geracao");
        if (geracao.isBlank()) {
            throw new IllegalArgumentException("Geração do acervo vazia");
        }
        raizes = List.copyOf(Objects.requireNonNull(raizes, "raizes"));
        intermediarias = List.copyOf(Objects.requireNonNull(intermediarias, "intermediarias"));
        if (raizes.isEmpty()) {
            throw new IllegalArgumentException("Acervo sem raízes");
        }
    }
}
