/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SafiraHealthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraHealthAutoConfiguration.class));

    @Test
    void shouldRegisterIndicatorWhenFonteDeConfiancaBeanExists() {
        runner.withBean("safiraFonteDeConfianca", FonteDeConfianca.class, () -> Optional::empty)
                .run(context -> assertThat(context).hasSingleBean(FonteDeConfiancaHealthIndicator.class)
                        .hasBean("fonteDeConfianca"));
    }

    @Test
    void shouldNotRegisterIndicatorWhenFonteDeConfiancaBeanIsMissing() {
        runner.run(context -> assertThat(context).doesNotHaveBean(FonteDeConfiancaHealthIndicator.class));
    }
}
