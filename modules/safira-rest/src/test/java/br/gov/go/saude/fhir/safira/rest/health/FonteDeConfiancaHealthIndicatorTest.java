/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import org.junit.jupiter.api.Test;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.Status;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class FonteDeConfiancaHealthIndicatorTest {

    @Test
    void shouldReportDownWhenCatalogIsUnavailable() {
        var indicador = new FonteDeConfiancaHealthIndicator(Optional::empty);

        Health health = indicador.health();

        assertThat(health.getStatus()).isEqualTo(Status.DOWN);
    }

    @Test
    void shouldReportUpWithGenerationAndCountsWhenCatalogIsAvailable() {
        var pki = TestPki.create();
        var acervo = new AcervoDeConfianca("g-42", List.of(pki.caCert), List.of(pki.caCert, pki.caCert));
        var indicador = new FonteDeConfiancaHealthIndicator(() -> Optional.of(acervo));

        Health health = indicador.health();

        assertThat(health.getStatus()).isEqualTo(Status.UP);
        assertThat(health.getDetails()).containsEntry("geracao", "g-42")
                .containsEntry("raizes", 1)
                .containsEntry("intermediarias", 2)
                .hasSize(3);
    }
}
