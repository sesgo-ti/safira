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
 * @param geracao        identificador opaco da geração, comparado apenas por {@code equals}, sem
 *                       ordem ("maior" não significa "mais nova"); o mesmo valor garante as mesmas
 *                       raízes e intermediárias, e conteúdo diferente exige valor diferente. Os
 *                       consumidores reaproveitam as fontes do DSS enquanto a geração não muda
 * @param raizes         únicas âncoras de confiança (ao menos uma); ao virar fontes do DSS vão
 *                       para a fonte confiável (trusted)
 * @param intermediarias pool NÃO confiável de ACs intermediárias, usado só para montar a cadeia;
 *                       vai para a fonte adjunta do DSS, que revalida cada uma até uma raiz
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

    /** Mostra só a geração e as contagens, sem despejar os certificados. */
    @Override
    public String toString() {
        return "AcervoDeConfianca[geracao=" + geracao + ", raizes=" + raizes.size()
                + ", intermediarias=" + intermediarias.size() + "]";
    }
}
