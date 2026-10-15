/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class AcervoDeConfiancaTest {

    private final X509Certificate raiz = mock(X509Certificate.class);
    private final X509Certificate intermediaria = mock(X509Certificate.class);

    @Test
    void shouldRejectAcervoWithoutRoots() {
        assertThatThrownBy(() -> new AcervoDeConfianca("g1", List.of(), List.of(intermediaria)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectBlankGeracao() {
        assertThatThrownBy(() -> new AcervoDeConfianca("  ", List.of(raiz), List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectNullGeracao() {
        assertThatThrownBy(() -> new AcervoDeConfianca(null, List.of(raiz), List.of()))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectNullLists() {
        assertThatThrownBy(() -> new AcervoDeConfianca("g1", null, List.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AcervoDeConfianca("g1", List.of(raiz), null))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectNullElements() {
        assertThatThrownBy(() -> new AcervoDeConfianca("g1", Arrays.asList(raiz, null), List.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AcervoDeConfianca("g1", List.of(raiz), Arrays.asList(intermediaria, null)))
                .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldCopyListsDefensively() {
        List<X509Certificate> raizes = new ArrayList<>(List.of(raiz));
        List<X509Certificate> intermediarias = new ArrayList<>(List.of(intermediaria));

        AcervoDeConfianca acervo = new AcervoDeConfianca("g1", raizes, intermediarias);
        raizes.clear();
        intermediarias.clear();

        assertThat(acervo.raizes()).containsExactly(raiz);
        assertThat(acervo.intermediarias()).containsExactly(intermediaria);
    }

    @Test
    void shouldExposeImmutableLists() {
        AcervoDeConfianca acervo = new AcervoDeConfianca("g1", List.of(raiz), List.of(intermediaria));

        assertThatThrownBy(() -> acervo.raizes().add(raiz))
                .isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> acervo.intermediarias().add(raiz))
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldAllowEmptyIntermediarias() {
        AcervoDeConfianca acervo = new AcervoDeConfianca("g1", List.of(raiz), List.of());

        assertThat(acervo.geracao()).isEqualTo("g1");
        assertThat(acervo.intermediarias()).isEmpty();
    }

    @Test
    void shouldShowOnlyGeracaoAndCountsInToString() {
        AcervoDeConfianca acervo = new AcervoDeConfianca("g1", List.of(raiz), List.of(intermediaria, intermediaria));

        assertThat(acervo.toString()).isEqualTo("AcervoDeConfianca[geracao=g1, raizes=1, intermediarias=2]");
    }
}
