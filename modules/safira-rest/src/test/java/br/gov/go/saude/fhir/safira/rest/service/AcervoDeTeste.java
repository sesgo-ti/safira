/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/** Acervo de teste com uma única raiz e geração própria a cada chamada. */
public final class AcervoDeTeste {

    private static final AtomicLong GERACOES = new AtomicLong();

    private AcervoDeTeste() {
    }

    public static Optional<AcervoDeConfianca> com(X509Certificate raiz) {
        return Optional.of(new AcervoDeConfianca("teste-" + GERACOES.incrementAndGet(), List.of(raiz), List.of()));
    }
}
