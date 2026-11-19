/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;

/**
 * Aplicação mínima dos testes de sistema do simulador como biblioteca: só as auto-configurações do
 * {@code safira-rest} e do {@code safira-simulador}, sem o inicializador que gera a PKI na partida.
 * A fonte de confiança vem das âncoras em arquivo ({@code SAFIRA_SIMULACAO_*}) ou, com o modo
 * desligado, de {@link ModoIcpBrasilDeTeste}.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
public class SimuladorTestApplication {
}
