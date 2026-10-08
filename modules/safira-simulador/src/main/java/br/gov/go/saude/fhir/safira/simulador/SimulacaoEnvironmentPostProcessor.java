/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.springframework.boot.EnvironmentPostProcessor;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.context.config.ConfigDataEnvironmentPostProcessor;
import org.springframework.core.Ordered;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;

import java.util.Map;

/**
 * Com {@code safira.simulacao.enabled=true}, desliga à força o bootstrap e o agendamento da
 * icpbrasil-truststore: no modo simulação o acervo do ITI nunca é baixado, mesmo que a
 * configuração (fora do perfil {@code simulacao}) os deixe ligados.
 */
public class SimulacaoEnvironmentPostProcessor implements EnvironmentPostProcessor, Ordered {

    static final String FONTE = "safiraSimulacaoSemAcervo";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        if ("true".equalsIgnoreCase(environment.getProperty("safira.simulacao.enabled"))) {
            environment.getPropertySources().addFirst(new MapPropertySource(FONTE, Map.of(
                    "icpbrasil-truststore.bootstrap.enabled", "false",
                    "icpbrasil-truststore.scheduling.enabled", "false")));
        }
    }

    @Override
    public int getOrder() {
        return ConfigDataEnvironmentPostProcessor.ORDER + 1;
    }
}
