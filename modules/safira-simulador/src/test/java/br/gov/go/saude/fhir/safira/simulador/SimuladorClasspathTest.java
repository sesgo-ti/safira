/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.junit.jupiter.api.Test;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A aplicação do simulador não leva a icpbrasil-truststore: nada baixa o acervo do ITI nem precisa
 * ser desligado à força (substitui o antigo {@code SimulacaoEnvironmentPostProcessor}).
 */
class SimuladorClasspathTest {

    @Test
    void shouldNotHaveTrustStoreLibraryOnClasspath() {
        assertThat(ClassUtils.isPresent("br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration",
                getClass().getClassLoader())).isFalse();
    }
}
