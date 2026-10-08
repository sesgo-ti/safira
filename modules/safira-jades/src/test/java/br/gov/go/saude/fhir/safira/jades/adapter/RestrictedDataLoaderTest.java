/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.service.http.proxy.ProxyConfig;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.apache.hc.client5.http.DnsResolver;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RestrictedDataLoaderTest {

    /** Guarda de teste: recusa loopback, privados (RFC 1918), link-local e registra o que viu. */
    private static final class RecordingGuard implements DestinationGuard {
        private final List<InetAddress> seen = new CopyOnWriteArrayList<>();
        private final boolean allowLoopback;

        private RecordingGuard(boolean allowLoopback) {
            this.allowLoopback = allowLoopback;
        }

        @Override
        public void check(String host, InetAddress address) {
            seen.add(address);
            if ((address.isLoopbackAddress() && !allowLoopback) || address.isSiteLocalAddress()
                    || address.isLinkLocalAddress() || address.isAnyLocalAddress()) {
                throw new IllegalArgumentException("destino interno " + address.getHostAddress());
            }
        }
    }

    private final AtomicInteger hits = new AtomicInteger();
    private HttpServer server;
    private String base;
    private int port;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/small", exchange -> {
            hits.incrementAndGet();
            respond(exchange, 200, new byte[16]);
        });
        server.createContext("/big", exchange -> respond(exchange, 200, new byte[4096]));
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", base + "/small");
            respond(exchange, 302, new byte[0]);
        });
        server.start();
        port = server.getAddress().getPort();
        base = "http://127.0.0.1:" + port;
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

    private static RestrictedDataLoader loader() {
        return new RestrictedDataLoader(null, 5, 1024, new RecordingGuard(true));
    }

    @Test
    void shouldRefuseInternalLiteralWithoutConnectingWhenGuardRejectsIt() {
        RecordingGuard guard = new RecordingGuard(false);
        RestrictedDataLoader loader = new RestrictedDataLoader(null, 5, 1024, guard);

        assertThatThrownBy(() -> loader.get(base + "/small")).isInstanceOf(DSSExternalResourceException.class);
        assertThat(hits).hasValue(0);
        assertThat(guard.seen).extracting(InetAddress::getHostAddress).containsExactly("127.0.0.1");
    }

    @Test
    void shouldRefuseMetadataPrivateAndIpv6LoopbackLiteralsWhenGuardRejectsThem() {
        RecordingGuard guard = new RecordingGuard(false);
        RestrictedDataLoader loader = new RestrictedDataLoader(null, 1, 1024, guard);

        for (String url : List.of("http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/ca.crl", "http://[::1]/ca.crl")) {
            assertThatThrownBy(() -> loader.get(url)).isInstanceOf(DSSExternalResourceException.class)
                    .hasStackTraceContaining("destino interno");
        }
        assertThat(guard.seen).hasSize(3);
    }

    @Test
    void shouldRefuseHostnameResolvingToInternalAddressWhenGuardRejectsIt() {
        RecordingGuard guard = new RecordingGuard(false);
        RestrictedDataLoader loader = new RestrictedDataLoader(null, 5, 1024, guard,
                fakeDns("ocsp.example", InetAddress.getLoopbackAddress()));

        assertThatThrownBy(() -> loader.get("http://ocsp.example:" + port + "/small"))
                .isInstanceOf(DSSExternalResourceException.class);
        assertThat(hits).hasValue(0);
    }

    @Test
    void shouldConnectThroughGuardedResolverWhenGuardAcceptsAddress() {
        RestrictedDataLoader loader = new RestrictedDataLoader(null, 5, 1024, new RecordingGuard(true),
                fakeDns("ocsp.example", InetAddress.getLoopbackAddress()));

        assertThat(loader.get("http://ocsp.example:" + port + "/small")).hasSize(16);
        assertThat(hits).hasValue(1);
    }

    private static DnsResolver fakeDns(String name, InetAddress address) {
        return new DnsResolver() {
            @Override
            public InetAddress[] resolve(String host) throws UnknownHostException {
                if (host.equals(name)) {
                    return new InetAddress[]{address};
                }
                throw new UnknownHostException(host);
            }

            @Override
            public String resolveCanonicalHostname(String host) {
                return host;
            }
        };
    }

    @Test
    void shouldRefuseProxyConfigurationWhenRequested() {
        assertThatThrownBy(() -> loader().setProxyConfig(new ProxyConfig())).isInstanceOf(UnsupportedOperationException.class);
        assertThatThrownBy(() -> loader().setUseSystemProperties(true)).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldIgnoreSystemProxyWhenJvmProxyPropertiesAreSet() {
        String previous = System.getProperty("http.proxyHost");
        System.setProperty("http.proxyHost", "203.0.113.1");
        System.setProperty("http.proxyPort", "9");
        try {
            assertThat(loader().get(base + "/small")).hasSize(16);
        } finally {
            if (previous == null) {
                System.clearProperty("http.proxyHost");
            } else {
                System.setProperty("http.proxyHost", previous);
            }
            System.clearProperty("http.proxyPort");
        }
    }

    @Test
    void shouldDownloadWhenResponseIsWithinLimit() {
        assertThat(loader().get(base + "/small")).hasSize(16);
    }

    @Test
    void shouldRejectResponseWhenLargerThanLimit() {
        assertThatThrownBy(() -> loader().get(base + "/big")).isInstanceOf(RuntimeException.class);
    }

    @Test
    void shouldNotFollowRedirectWhenServerRedirects() {
        assertThatThrownBy(() -> loader().get(base + "/redirect")).isInstanceOf(DSSExternalResourceException.class);
    }

    @Test
    void shouldRejectFileUrlWhenRequested() throws IOException {
        Path file = Files.createTempFile("safira", ".crl");
        Files.write(file, new byte[16]);

        assertThatThrownBy(() -> loader().get(file.toUri().toString())).isInstanceOf(DSSExternalResourceException.class);
    }

    @Test
    void shouldRejectLdapAndFtpUrlsWhenRequested() {
        assertThatThrownBy(() -> loader().get("ldap://127.0.0.1/cn=ca?certificateRevocationList"))
                .isInstanceOf(DSSExternalResourceException.class);
        assertThatThrownBy(() -> loader().get("ftp://127.0.0.1/ca.crl")).isInstanceOf(DSSExternalResourceException.class);
    }
}
