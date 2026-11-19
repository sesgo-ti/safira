/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Contexto Spring (não web) da CLI: só auto-configuração — serviços do {@code safira-rest} e a fonte de
 * confiança do modo. Sem varredura de componentes.
 */
@SpringBootConfiguration(proxyBeanMethods = false)
@EnableAutoConfiguration
class SafiraCliAplicacao {
}
