/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FonteDeConfiancaSimuladaTest {

    @TempDir
    static Path saida;

    static X509Certificate raiz;
    static X509Certificate ac;
    static X509Certificate outraRaiz;
    static X509Certificate outraAc;

    @BeforeAll
    static void gerar() throws Exception {
        Resultado pki = GeradorPkiSimulada.gerar(saida.resolve("a"), Opcoes.padrao());
        Resultado outra = GeradorPkiSimulada.gerar(saida.resolve("b"), Opcoes.padrao());
        raiz = SafiraSimulacaoAutoConfigurationTest.certificado(pki.raiz());
        ac = SafiraSimulacaoAutoConfigurationTest.certificado(pki.ac());
        outraRaiz = SafiraSimulacaoAutoConfigurationTest.certificado(outra.raiz());
        outraAc = SafiraSimulacaoAutoConfigurationTest.certificado(outra.ac());
    }

    private static String geracao(List<X509Certificate> raizes, List<X509Certificate> acs) {
        return new FonteDeConfiancaSimulada(raizes, acs).atual().orElseThrow().geracao();
    }

    @Test
    void shouldDeliverRootsAndIntermediatesWhenCreated() {
        AcervoDeConfianca acervo = new FonteDeConfiancaSimulada(List.of(raiz), List.of(ac)).atual().orElseThrow();

        assertThat(acervo.raizes()).containsExactly(raiz);
        assertThat(acervo.intermediarias()).containsExactly(ac);
    }

    @Test
    void shouldKeepSameGenerationWhenContentIsEqual() {
        assertThat(geracao(List.of(raiz), List.of(ac))).isEqualTo(geracao(List.of(raiz), List.of(ac)));
    }

    @Test
    void shouldChangeGenerationWhenRootsDiffer() {
        assertThat(geracao(List.of(raiz), List.of(ac))).isNotEqualTo(geracao(List.of(outraRaiz), List.of(ac)));
    }

    @Test
    void shouldChangeGenerationWhenIntermediatesDiffer() {
        assertThat(geracao(List.of(raiz), List.of(ac))).isNotEqualTo(geracao(List.of(raiz), List.of(outraAc)));
    }

    @Test
    void shouldChangeGenerationWhenIntermediateMovesToRoots() {
        assertThat(geracao(List.of(raiz), List.of(ac))).isNotEqualTo(geracao(List.of(raiz, ac), List.of()));
    }
}
