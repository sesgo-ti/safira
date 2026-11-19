/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * Porta da fonte de carimbo do tempo (RFC 3161) usada no JAdES-B-T. O produto usa a TSA online
 * ({@link #online()}); o simulador troca por uma TSA em memória, sem rede.
 */
@FunctionalInterface
public interface TspSourceFactory {

    /**
     * @param tsaUrl         URL HTTPS da TSA ({@code safira.operational.verification.tsa-url})
     * @param timeoutSeconds timeout de conexão/resposta em segundos
     * @param policyOid      OID da política TSA solicitada ({@code reqPolicy})
     */
    TSPSource create(String tsaUrl, int timeoutSeconds, String policyOid);

    /** TSA online por {@link TspSources#online}. */
    static TspSourceFactory online() {
        return TspSources::online;
    }
}
