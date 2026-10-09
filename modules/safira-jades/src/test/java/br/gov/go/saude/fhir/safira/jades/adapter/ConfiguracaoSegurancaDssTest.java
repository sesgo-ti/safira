/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Trava da configuração de rede/confiança do DSS produzida por {@link CertificateVerifierFactory}:
 * quem afrouxar qualquer item abaixo quebra o build. Política de assinatura sem rede: ver
 * os testes da F02.
 */
class ConfiguracaoSegurancaDssTest {

    private final AtomicInteger hits = new AtomicInteger();
    private final List<InetAddress> guarded = new CopyOnWriteArrayList<>();
    private HttpServer server;
    private String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/redirect", exchange -> {
            hits.incrementAndGet();
            exchange.getResponseHeaders().set("Location", base + "/small");
            respond(exchange, 302, new byte[0]);
        });
        server.createContext("/small", exchange -> {
            hits.incrementAndGet();
            respond(exchange, 200, new byte[16]);
        });
        server.start();
        base = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static void respond(HttpExchange exchange, int status, byte[] body) throws IOException {
        try (exchange) {
            exchange.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
            if (body.length > 0) {
                try (OutputStream out = exchange.getResponseBody()) {
                    out.write(body);
                }
            }
        }
    }

    private List<RestrictedDataLoader> loaders(DestinationGuard guard) {
        return CertificateVerifierFactory.online(7, 9, guard).dataLoaders();
    }

    private List<RestrictedDataLoader> loaders() {
        return loaders((host, address) -> guarded.add(address));
    }

    @Test
    void shouldNotConfigureAiaWhenVerifierIsCreated() {
        assertThat(verifier().getAIASource()).isNull();
    }

    @Test
    void shouldNotCheckRevocationForUntrustedChainsWhenVerifierIsCreated() {
        assertThat(verifier().isCheckRevocationForUntrustedChains()).isFalse();
    }

    @Test
    void shouldUseOnlyOcspAndCrlSourcesWhenVerifierIsCreated() {
        assertThat(verifier().getOcspSource()).isNotNull();
        assertThat(verifier().getCrlSource()).isNotNull();
    }

    private static CommonCertificateVerifier verifier() {
        TestPki pki = TestPki.create();
        return CertificateVerifierFactory.online(7, 9, (host, address) -> { })
                .create(CertificateVerifierFactory.acervo(List.of(pki.caCert), List.of()), List.of());
    }

    @Test
    void shouldRefuseFileFtpAndLdapWhenLoaderComesFromFactory() {
        for (RestrictedDataLoader loader : loaders()) {
            assertThatThrownBy(() -> loader.get("file:///etc/hosts")).isInstanceOf(DSSExternalResourceException.class);
            assertThatThrownBy(() -> loader.get("ftp://127.0.0.1/ca.crl")).isInstanceOf(DSSExternalResourceException.class);
            assertThatThrownBy(() -> loader.get("ldap://127.0.0.1/cn=ca")).isInstanceOf(DSSExternalResourceException.class);
        }
        assertThat(guarded).isEmpty();
    }

    @Test
    void shouldNotFollowRedirectWhenLoaderComesFromFactory() {
        for (RestrictedDataLoader loader : loaders()) {
            assertThat(loader.isRedirectsEnabled()).isFalse();
            assertThatThrownBy(() -> loader.get(base + "/redirect")).isInstanceOf(DSSExternalResourceException.class);
        }
        assertThat(hits).hasValue(2);
    }

    @Test
    void shouldCapResponseAt64MiBWhenLoaderComesFromFactory() {
        assertThat(CertificateVerifierFactory.MAX_RESPONSE_BYTES).isEqualTo(64 * 1024 * 1024);
        assertThat(loaders()).allSatisfy(loader ->
                assertThat(loader.getMaxResponseBytes()).isEqualTo(CertificateVerifierFactory.MAX_RESPONSE_BYTES));
    }

    @Test
    void shouldConfigureTimeoutsWhenLoaderComesFromFactory() {
        List<RestrictedDataLoader> loaders = loaders();

        assertThat(loaders).hasSize(2);
        assertThat(loaders.get(0)).satisfies(loader -> assertTimeouts(loader, 7000));
        assertThat(loaders.get(1)).satisfies(loader -> assertTimeouts(loader, 9000));
    }

    private static void assertTimeouts(RestrictedDataLoader loader, int millis) {
        assertThat(loader.getTimeoutConnection()).isEqualTo(millis);
        assertThat(loader.getTimeoutConnectionRequest()).isEqualTo(millis);
        assertThat(loader.getTimeoutResponse()).isEqualTo(millis);
        assertThat(loader.getTimeoutSocket()).isEqualTo(millis);
    }

    @Test
    void shouldRefuseProxyWhenLoaderComesFromFactory() {
        for (RestrictedDataLoader loader : loaders()) {
            assertThatThrownBy(() -> loader.setProxyConfig(new ProxyConfig())).isInstanceOf(UnsupportedOperationException.class);
            assertThatThrownBy(() -> loader.setUseSystemProperties(true)).isInstanceOf(UnsupportedOperationException.class);
        }
    }

    @Test
    void shouldApplyDestinationGuardWhenLoaderComesFromFactory() {
        DestinationGuard refuseAll = (host, address) -> {
            throw new IllegalArgumentException("destino recusado");
        };
        for (RestrictedDataLoader loader : loaders(refuseAll)) {
            assertThatThrownBy(() -> loader.get(base + "/small")).isInstanceOf(DSSExternalResourceException.class);
        }
        assertThat(hits).hasValue(0);
    }

    @Test
    void shouldPassEveryResolvedAddressToGuardWhenLoaderComesFromFactory() {
        loaders().forEach(loader -> loader.get(base + "/small"));

        assertThat(guarded).extracting(InetAddress::getHostAddress).containsOnly("127.0.0.1").hasSize(2);
    }
}
