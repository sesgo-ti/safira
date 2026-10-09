/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.app.icpbrasil.FonteDeConfiancaIcpBrasil;
import br.gov.go.saude.fhir.safira.simulador.FonteDeConfiancaSimulada;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Só uma fonte de confiança por modo: os modos nunca se misturam, nem por configuração externa. */
class ModoExclusivoTest {

    @TempDir
    Path diretorio;

    @AfterEach
    void limpar() {
        System.clearProperty("safira.simulacao.enabled");
    }

    @Test
    void shouldKeepOnlySimulatedTrustInSimulationMode() {
        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.SIMULACAO, diretorio.resolve("pki"), null, false)) {
            Map<String, FonteDeConfianca> fontes = contexto.aplicacao().getBeansOfType(FonteDeConfianca.class);

            assertThat(fontes).hasSize(1);
            assertThat(fontes.values().iterator().next()).isInstanceOf(FonteDeConfiancaSimulada.class);
            assertThat(contexto.aplicacao().getBeansOfType(TrustMaterialSource.class)).isEmpty();
            assertThat(contexto.aplicacao().getBeansOfType(PkiPersistida.class)).hasSize(1);
        }
    }

    @Test
    void shouldKeepOnlyIcpBrasilTrustEvenWhenSimulationIsEnabledByEnvironment() {
        System.setProperty("safira.simulacao.enabled", "true");

        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.ICPBRASIL, null, null, false)) {
            Map<String, FonteDeConfianca> fontes = contexto.aplicacao().getBeansOfType(FonteDeConfianca.class);

            assertThat(fontes).hasSize(1);
            assertThat(fontes.values().iterator().next()).isInstanceOf(FonteDeConfiancaIcpBrasil.class);
            assertThat(contexto.aplicacao().getBeansOfType(PkiPersistida.class)).isEmpty();
        }
    }
}
