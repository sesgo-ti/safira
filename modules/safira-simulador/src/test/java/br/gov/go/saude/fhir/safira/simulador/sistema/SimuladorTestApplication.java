/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Aplicação mínima dos testes de sistema do simulador: só as auto-configurações do
 * {@code safira-rest} e do {@code safira-simulador}, sem o {@code safira-app}. A fonte de confiança
 * vem do simulador (perfil {@code simulacao}) ou, com o modo desligado, de {@link ModoIcpBrasilDeTeste}.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
public class SimuladorTestApplication {
}
