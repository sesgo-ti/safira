/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

import br.gov.go.saude.fhir.safira.engine.config.SafiraEngineAutoConfiguration;
import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Falha fechada na partida: sem filtro de destino de rede ({@link DestinationGuard}) ou sem porta de
 * confiança ({@link FonteDeConfianca}) o contexto não sobe, mesmo com a icpbrasil-truststore presente.
 */
class SafiraAppFailClosedTest {

    private static final DestinationGuard RECUSA_TUDO = (host, address) -> {
        throw new IllegalStateException("sem rede nos testes");
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraEngineAutoConfiguration.class,
                    TrustStoreAutoConfiguration.class, SafiraStepsAutoConfiguration.class))
            .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                    "icpbrasil-truststore.scheduling.enabled=false",
                    "icpbrasil-truststore.filesystem.base-dir=target/icpbrasil-truststore-fail-closed");

    @Test
    void shouldFailStartupWhenDestinationGuardIsMissing() {
        runner.withBean(FonteDeConfianca.class, () -> Optional::empty)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining(DestinationGuard.class.getName());
                });
    }

    @Test
    void shouldFailStartupWhenFonteDeConfiancaIsMissing() {
        runner.withBean(DestinationGuard.class, () -> RECUSA_TUDO)
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining(FonteDeConfianca.class.getName());
                });
    }

    @Test
    void shouldWireIcpBrasilAdaptersWhenAppConfigurationIsPresent() {
        runner.withConfiguration(AutoConfigurations.of(SafiraIcpBrasilAutoConfiguration.class))
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(FonteDeConfianca.class)).isInstanceOf(FonteDeConfiancaIcpBrasil.class);
                    assertThat(context.getBean(DestinationGuard.class)).isInstanceOf(DownloadPolicyGuard.class);
                });
    }

    @Test
    void shouldStartWhenDestinationGuardAndFonteDeConfiancaArePresent() {
        runner.withBean(DestinationGuard.class, () -> RECUSA_TUDO)
                .withBean(FonteDeConfianca.class, () -> Optional::empty)
                .run(context -> assertThat(context).hasNotFailed());
    }
}
