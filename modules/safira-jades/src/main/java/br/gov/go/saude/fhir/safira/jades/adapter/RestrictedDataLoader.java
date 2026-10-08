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
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.SystemDefaultDnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.io.HttpClientConnectionManager;
import org.apache.hc.core5.http.HttpEntity;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;

import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;

/**
 * {@link CommonsDataLoader} para downloads disparados por URLs presentes em certificados
 * (AIA {@code caIssuers}, OCSP, CDP): somente HTTP/HTTPS, sem redirecionamentos, com timeouts,
 * teto de tamanho de resposta e {@link DestinationGuard} aplicado a cada endereço resolvido na
 * conexão (as URLs vêm de quem envia a assinatura: SSRF).
 *
 * <p>O {@link CommonsDataLoader} do DSS 6.4 aceita também {@code file:}, {@code ftp:} e
 * {@code ldap:} e não limita o tamanho da resposta; ambas as restrições são aplicadas pelos
 * pontos de extensão do próprio DSS (métodos protegidos e {@code HttpClientResponseHandler}).
 * O filtro de destino entra pelo {@link DnsResolver} do connection manager; não há proxy
 * configurado, então o endereço resolvido é o próprio destino.
 */
public class RestrictedDataLoader extends CommonsDataLoader {

    private static final long serialVersionUID = 1L;

    private final int maxResponseBytes;
    private final transient DnsResolver dnsResolver;

    /**
     * @param contentType      {@code Content-Type} das requisições POST (nulo para GET puro)
     * @param timeoutSeconds   timeout de conexão, de obtenção de conexão e de resposta
     * @param maxResponseBytes tamanho máximo aceito para o corpo da resposta
     * @param guard            política de destino aplicada a cada endereço resolvido
     */
    public RestrictedDataLoader(String contentType, int timeoutSeconds, int maxResponseBytes, DestinationGuard guard) {
        this(contentType, timeoutSeconds, maxResponseBytes, guard, SystemDefaultDnsResolver.INSTANCE);
    }

    RestrictedDataLoader(String contentType, int timeoutSeconds, int maxResponseBytes, DestinationGuard guard,
                         DnsResolver resolver) {
        super(contentType);
        this.dnsResolver = new GuardedDnsResolver(resolver, Objects.requireNonNull(guard, "guard"));
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

    /** Mesmo connection manager do {@link CommonsDataLoader}, com o {@link GuardedDnsResolver}. */
    @Override
    protected HttpClientConnectionManager getConnectionManager() {
        PoolingHttpClientConnectionManager manager = PoolingHttpClientConnectionManagerBuilder.create()
                .setDnsResolver(dnsResolver)
                .setTlsSocketStrategy(getTlsSocketStrategy())
                .setDefaultSocketConfig(getSocketConfig())
                .setMaxConnTotal(getConnectionsMaxTotal())
                .setMaxConnPerRoute(getConnectionsMaxPerRoute())
                .build();
        manager.setDefaultConnectionConfig(ConnectionConfig.custom()
                .setConnectTimeout(Timeout.ofMilliseconds(getTimeoutConnection()))
                .setTimeToLive(TimeValue.ofMilliseconds(getConnectionTimeToLive()))
                .build());
        return manager;
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
