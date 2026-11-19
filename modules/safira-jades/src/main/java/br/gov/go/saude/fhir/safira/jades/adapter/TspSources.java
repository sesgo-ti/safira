/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.service.SecureRandomNonceSource;
import eu.europa.esig.dss.service.http.commons.TimestampDataLoader;
import eu.europa.esig.dss.service.tsp.OnlineTSPSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * Fábrica de fontes TSP (RFC 3161) a partir da configuração operacional do Safira
 * ({@code safira.operational.verification.tsa-url} / {@code tsa-timeout}) e da política TSA
 * selecionada em {@code safira.policy.tsa-policies}.
 */
public final class TspSources {

    private TspSources() {
    }

    /**
     * Fonte TSP online: POST {@code application/timestamp-query} com nonce aleatório,
     * {@code certReq=true} e {@code reqPolicy} (criar 12.2). O DSS confere nonce, message
     * imprint e política da resposta contra a requisição.
     *
     * @param tsaUrl         URL HTTPS da TSA
     * @param timeoutSeconds timeout de conexão/resposta em segundos
     * @param policyOid      OID da política TSA solicitada ({@code reqPolicy})
     */
    public static TSPSource online(String tsaUrl, int timeoutSeconds, String policyOid) {
        TimestampDataLoader loader = new TimestampDataLoader();
        int timeoutMillis = Math.multiplyExact(timeoutSeconds, 1000);
        loader.setTimeoutConnection(timeoutMillis);
        loader.setTimeoutConnectionRequest(timeoutMillis);
        loader.setTimeoutResponse(timeoutMillis);
        loader.setTimeoutSocket(timeoutMillis);
        OnlineTSPSource source = new OnlineTSPSource(tsaUrl, loader);
        source.setPolicyOid(policyOid);
        source.setNonceSource(new SecureRandomNonceSource());
        return source;
    }
}
