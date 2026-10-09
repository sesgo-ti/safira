/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;

/**
 * Stub HTTP mínimo (RFC 3161 sobre HTTP, em {@code 127.0.0.1}) da TSA simulada, para os cenários
 * em que o código sob teste obtém o carimbo por URL. A emissão é a da {@link PkiIcpSimulada#fonteTsp()}.
 */
public final class TsaHttpLocal implements AutoCloseable {

    private final HttpServer servidor;

    TsaHttpLocal(TsaSimulada tsa) {
        try {
            servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao subir a TSA HTTP local", e);
        }
        servidor.createContext("/tsa", troca -> {
            try (troca) {
                byte[] corpo;
                try {
                    corpo = tsa.responder(troca.getRequestBody().readAllBytes());
                } catch (RuntimeException e) {
                    troca.sendResponseHeaders(500, -1);
                    return;
                }
                troca.getResponseHeaders().set("Content-Type", "application/timestamp-reply");
                troca.sendResponseHeaders(200, corpo.length);
                try (OutputStream saida = troca.getResponseBody()) {
                    saida.write(corpo);
                }
            }
        });
        servidor.start();
    }

    public String url() {
        return "http://127.0.0.1:" + servidor.getAddress().getPort() + "/tsa";
    }

    @Override
    public void close() {
        servidor.stop(0);
    }
}
