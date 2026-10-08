/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RestrictedDataLoaderTest {

    private HttpServer server;
    private String base;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/small", exchange -> respond(exchange, 200, new byte[16]));
        server.createContext("/big", exchange -> respond(exchange, 200, new byte[4096]));
        server.createContext("/redirect", exchange -> {
            exchange.getResponseHeaders().set("Location", base + "/small");
            respond(exchange, 302, new byte[0]);
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

    private static RestrictedDataLoader loader() {
        return new RestrictedDataLoader(null, 5, 1024);
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
