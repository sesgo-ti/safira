/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * Fábrica de fontes TSP (RFC 3161) a partir da configuração operacional do Safira
 * ({@code safira.operational.verification.tsa-url} / {@code tsa-timeout}).
 */
public final class TspSources {

    private TspSources() {
    }

    /**
     * Fonte TSP online: POST {@code application/timestamp-query} para a TSA configurada.
     *
     * @param tsaUrl         URL HTTPS da TSA
     * @param timeoutSeconds timeout de conexão/resposta em segundos
     */
    public static TSPSource online(String tsaUrl, int timeoutSeconds) {
        TimestampDataLoader loader = new TimestampDataLoader();
        int timeoutMillis = Math.multiplyExact(timeoutSeconds, 1000);
        loader.setTimeoutConnection(timeoutMillis);
        loader.setTimeoutConnectionRequest(timeoutMillis);
        loader.setTimeoutResponse(timeoutMillis);
        loader.setTimeoutSocket(timeoutMillis);
        return new OnlineTSPSource(tsaUrl, loader);
    }
}
