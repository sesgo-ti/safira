/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/** Só as sondas do Actuator ficam fora da contagem de uso. */
class MonitorDeOciosidadeTest {

    @Test
    void shouldIgnoreOnlyActuatorPathsWhenCountingUse() {
        assertThat(MonitorDeOciosidade.contaComoUso("/actuator/health/readiness")).isFalse();
        assertThat(MonitorDeOciosidade.contaComoUso("/actuator")).isFalse();
        assertThat(MonitorDeOciosidade.contaComoUso("/actuatorx")).isTrue();
        assertThat(MonitorDeOciosidade.contaComoUso("/assinar")).isTrue();
    }
}
