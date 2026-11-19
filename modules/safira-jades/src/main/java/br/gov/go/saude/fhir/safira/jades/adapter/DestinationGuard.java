/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import java.net.InetAddress;

/**
 * Política de destino dos downloads do DSS, aplicada a cada endereço resolvido no momento da
 * conexão (fecha a janela de DNS rebinding entre verificação e uso).
 */
@FunctionalInterface
public interface DestinationGuard {

    /**
     * Recusa o destino lançando exceção não verificada.
     *
     * @param host    host da URL, como consta do certificado
     * @param address endereço resolvido que seria usado na conexão
     */
    void check(String host, InetAddress address);
}
