/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.OCSPDataLoader;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

/**
 * Fábrica de fontes de revogação online (AIA/CDP do próprio certificado) com timeouts
 * derivados da configuração operacional do Safira.
 */
public final class OnlineRevocationSources {

    private OnlineRevocationSources() {
    }

    public static RevocationSource<OCSP> ocsp(int timeoutSeconds) {
        OCSPDataLoader loader = new OCSPDataLoader();
        applyTimeouts(loader, timeoutSeconds);
        return new OnlineOCSPSource(loader);
    }

    public static RevocationSource<CRL> crl(int timeoutSeconds) {
        CommonsDataLoader loader = new CommonsDataLoader();
        applyTimeouts(loader, timeoutSeconds);
        return new OnlineCRLSource(loader);
    }

    private static void applyTimeouts(CommonsDataLoader loader, int timeoutSeconds) {
        int timeoutMillis = Math.multiplyExact(timeoutSeconds, 1000);
        loader.setTimeoutConnection(timeoutMillis);
        loader.setTimeoutConnectionRequest(timeoutMillis);
        loader.setTimeoutResponse(timeoutMillis);
        loader.setTimeoutSocket(timeoutMillis);
    }
}
