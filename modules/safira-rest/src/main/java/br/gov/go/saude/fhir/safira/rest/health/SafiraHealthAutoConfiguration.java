/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.annotation.Bean;

/** Registra o indicador de saúde da porta de confiança quando o Actuator está no classpath. */
@AutoConfiguration(after = SafiraStepsAutoConfiguration.class)
@ConditionalOnClass(HealthIndicator.class)
public class SafiraHealthAutoConfiguration {

    @Bean("fonteDeConfianca")
    @ConditionalOnBean(FonteDeConfianca.class)
    public FonteDeConfiancaHealthIndicator fonteDeConfiancaHealthIndicator(FonteDeConfianca fonteDeConfianca) {
        return new FonteDeConfiancaHealthIndicator(fonteDeConfianca);
    }
}
