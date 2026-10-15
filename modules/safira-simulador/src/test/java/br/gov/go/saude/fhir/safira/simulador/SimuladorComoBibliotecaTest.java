/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.junit.jupiter.api.Test;
import org.springframework.boot.WebApplicationType;
import org.springframework.boot.autoconfigure.ImportAutoConfiguration;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * O jar comum do simulador no classpath de outra aplicação (ex.: a CLI) não liga o modo simulação:
 * a configuração da aplicação do simulador só vale com o perfil {@code simulador}.
 */
class SimuladorComoBibliotecaTest {

    @Configuration(proxyBeanMethods = false)
    @ImportAutoConfiguration(SafiraSimulacaoAutoConfiguration.class)
    static class OutraAplicacao {
    }

    @Test
    void shouldNotEnableSimulationWhenSimulatorProfileIsNotActive() {
        try (ConfigurableApplicationContext contexto = new SpringApplicationBuilder(OutraAplicacao.class)
                .web(WebApplicationType.NONE)
                .run()) {
            assertThat(contexto.getEnvironment().getProperty("safira.simulacao.enabled")).isNull();
            assertThat(contexto.getBeansOfType(FonteDeConfianca.class)).isEmpty();
        }
    }
}
