/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.function.UnaryOperator;

/**
 * Stub HTTP mínimo da TSA simulada em {@code 127.0.0.1}, para os cenários em que o código sob teste
 * fala HTTP de verdade: {@code /tsa} (RFC 3161) e {@code /ocsp} (RFC 6960, sempre {@code GOOD}). O
 * certificado servido é o da TSA da PKI reemitido com AIA OCSP apontando para este {@code /ocsp}
 * (porta conhecida só após subir o servidor). Emissões pelas fontes em memória da {@link PkiIcpSimulada}.
 */
public final class TsaHttpLocal implements AutoCloseable {

    private final HttpServer servidor;
    private final X509Certificate certificado;

    TsaHttpLocal(PkiIcpSimulada pki) {
        try {
            servidor = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao subir a TSA HTTP local", e);
        }
        certificado = pki.tsaComOcsp(base() + "/ocsp");
        TsaSimulada tsa = pki.tsaServida(certificado);
        servidor.createContext("/tsa", troca -> responder(troca, "application/timestamp-reply", tsa::responder));
        servidor.createContext("/ocsp", troca -> responder(troca, "application/ocsp-response", pki::ocspBomPara));
        servidor.start();
    }

    public String url() {
        return base() + "/tsa";
    }

    /** Certificado da TSA servido nos carimbos (com AIA OCSP para este stub). */
    public X509Certificate certificado() {
        return certificado;
    }

    @Override
    public void close() {
        servidor.stop(0);
    }

    private String base() {
        return "http://127.0.0.1:" + servidor.getAddress().getPort();
    }

    private static void responder(HttpExchange troca, String tipo, UnaryOperator<byte[]> emissor) throws IOException {
        try (troca) {
            byte[] corpo;
            try {
                corpo = emissor.apply(troca.getRequestBody().readAllBytes());
            } catch (RuntimeException e) {
                troca.sendResponseHeaders(500, -1);
                return;
            }
            troca.getResponseHeaders().set("Content-Type", tipo);
            troca.sendResponseHeaders(200, corpo.length);
            try (OutputStream saida = troca.getResponseBody()) {
                saida.write(corpo);
            }
        }
    }
}
