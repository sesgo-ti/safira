/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.DSSException;
import eu.europa.esig.dss.service.http.commons.CommonsDataLoader;
import eu.europa.esig.dss.service.http.commons.CommonsHttpClientResponseHandler;
import eu.europa.esig.dss.spi.client.http.MaxSizeInputStream;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.apache.hc.core5.http.HttpEntity;

import java.io.IOException;
import java.io.InputStream;

/**
 * {@link CommonsDataLoader} para downloads disparados por URLs presentes em certificados
 * (AIA {@code caIssuers}, OCSP, CDP): somente HTTP/HTTPS, sem redirecionamentos, com timeouts
 * e teto de tamanho de resposta.
 *
 * <p>O {@link CommonsDataLoader} do DSS 6.4 aceita também {@code file:}, {@code ftp:} e
 * {@code ldap:} e não limita o tamanho da resposta; ambas as restrições são aplicadas pelos
 * pontos de extensão do próprio DSS (métodos protegidos e {@code HttpClientResponseHandler}).
 */
public class RestrictedDataLoader extends CommonsDataLoader {

    private static final long serialVersionUID = 1L;

    private final int maxResponseBytes;

    /**
     * @param contentType      {@code Content-Type} das requisições POST (nulo para GET puro)
     * @param timeoutSeconds   timeout de conexão, de obtenção de conexão e de resposta
     * @param maxResponseBytes tamanho máximo aceito para o corpo da resposta
     */
    public RestrictedDataLoader(String contentType, int timeoutSeconds, int maxResponseBytes) {
        super(contentType);
        int timeoutMillis = Math.multiplyExact(timeoutSeconds, 1000);
        setTimeoutConnection(timeoutMillis);
        setTimeoutConnectionRequest(timeoutMillis);
        setTimeoutResponse(timeoutMillis);
        setTimeoutSocket(timeoutMillis);
        setRedirectsEnabled(false);
        this.maxResponseBytes = maxResponseBytes;
        setHttpClientResponseHandler(new BoundedResponseHandler(maxResponseBytes));
    }

    public int getMaxResponseBytes() {
        return maxResponseBytes;
    }

    @Override
    protected byte[] fileGet(String urlString) {
        throw unsupported(urlString);
    }

    @Override
    protected byte[] ftpGet(String urlString) {
        throw unsupported(urlString);
    }

    @Override
    protected byte[] ldapGet(String urlString) {
        throw unsupported(urlString);
    }

    private static DSSException unsupported(String urlString) {
        return new DSSExternalResourceException("Protocolo não admitido (somente HTTP/HTTPS): " + urlString);
    }

    /** Lê o corpo da resposta interrompendo ao exceder o limite configurado. */
    private static final class BoundedResponseHandler extends CommonsHttpClientResponseHandler {

        private final int maxResponseBytes;

        private BoundedResponseHandler(int maxResponseBytes) {
            this.maxResponseBytes = maxResponseBytes;
        }

        @Override
        protected byte[] getContent(HttpEntity responseEntity) throws IOException {
            try (InputStream content = new MaxSizeInputStream(responseEntity.getContent(), maxResponseBytes, null)) {
                return content.readAllBytes();
            }
        }
    }
}
