/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.junit.jupiter.api.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SimulacaoEnvironmentPostProcessorTest {

    private final SimulacaoEnvironmentPostProcessor processor = new SimulacaoEnvironmentPostProcessor();

    @Test
    void shouldForceTrustStoreBootstrapAndSchedulingOffWhenSimulationIsEnabled() {
        StandardEnvironment environment = ambiente(Map.of("safira.simulacao.enabled", "true",
                "icpbrasil-truststore.bootstrap.enabled", "true", "icpbrasil-truststore.scheduling.enabled", "true"));

        processor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("icpbrasil-truststore.bootstrap.enabled")).isEqualTo("false");
        assertThat(environment.getProperty("icpbrasil-truststore.scheduling.enabled")).isEqualTo("false");
    }

    @Test
    void shouldKeepTrustStoreSettingsWhenSimulationIsDisabled() {
        StandardEnvironment environment = ambiente(Map.of("safira.simulacao.enabled", "false",
                "icpbrasil-truststore.bootstrap.enabled", "true"));

        processor.postProcessEnvironment(environment, new SpringApplication());

        assertThat(environment.getProperty("icpbrasil-truststore.bootstrap.enabled")).isEqualTo("true");
        assertThat(environment.getPropertySources().contains(SimulacaoEnvironmentPostProcessor.FONTE)).isFalse();
    }

    private static StandardEnvironment ambiente(Map<String, Object> propriedades) {
        StandardEnvironment environment = new StandardEnvironment();
        environment.getPropertySources().addFirst(new MapPropertySource("teste", propriedades));
        return environment;
    }
}
