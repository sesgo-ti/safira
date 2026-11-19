/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.support;

import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;

/**
 * {@link FonteDeConfianca} fixa para testes: autoassinados viram raízes, os demais intermediárias.
 * Cada fonte tem geração própria; sem raízes, entrega vazio (como acervo indisponível).
 */
public final class FonteDeTeste {

    private static final AtomicLong GERACOES = new AtomicLong();

    private FonteDeTeste() {
    }

    public static FonteDeConfianca com(X509Certificate... certificados) {
        List<X509Certificate> todos = Arrays.asList(certificados);
        List<X509Certificate> raizes = todos.stream().filter(FonteDeTeste::autoassinado).toList();
        if (raizes.isEmpty()) {
            return Optional::empty;
        }
        List<X509Certificate> intermediarias = todos.stream().filter(c -> !autoassinado(c)).toList();
        Optional<AcervoDeConfianca> acervo = Optional.of(new AcervoDeConfianca(
                "teste-" + GERACOES.incrementAndGet(), raizes, intermediarias));
        return () -> acervo;
    }

    private static boolean autoassinado(X509Certificate certificado) {
        if (!certificado.getSubjectX500Principal().equals(certificado.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificado.verify(certificado.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
