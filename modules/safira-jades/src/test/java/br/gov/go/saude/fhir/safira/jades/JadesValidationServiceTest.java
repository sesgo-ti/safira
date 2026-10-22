/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import com.sun.net.httpserver.HttpServer;
import eu.europa.esig.dss.model.Policy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class JadesValidationServiceTest {

    private static final long REFERENCE_TIMESTAMP = Instant.now().getEpochSecond();

    private HttpServer server;
    private final AtomicInteger requests = new AtomicInteger();

    @BeforeEach
    void startServer() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            byte[] body = "politica".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, body.length);
            exchange.getResponseBody().write(body);
            exchange.close();
        });
        server.start();
    }

    @AfterEach
    void stopServer() {
        server.stop(0);
    }

    @Test
    void shouldNotRequestSignaturePolicyUriWhenValidatingSignature() throws Exception {
        PkiIcpSimulada pki = PkiIcpSimulada.criar();
        String policyUri = "http://127.0.0.1:" + server.getAddress().getPort() + "/politica";
        Policy policy = new Policy();
        policy.setId("https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0");
        policy.setSpuri(policyUri);
        JadesSigningService signing = new JadesSigningService();
        byte[] payload = MessageDigest.getInstance("SHA-256")
                .digest("conteudo".getBytes(StandardCharsets.UTF_8));
        JadesSigningSession session = signing.newSession(new JadesSigningService.Request(
                pki.cadeia(), payload, REFERENCE_TIMESTAMP, policy.getId()));
        session.parameters().bLevel().setSignaturePolicy(policy);
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pki.chavesSignatario().getPrivate());
        signer.update(signing.dataToSign(session));
        String jws = signing.sign(session, signer.sign());

        new JadesValidationService().validate(jws,
                CertificateVerifierFactory.offline(pki.fonteOcsp(), null)
                        .create(CertificateVerifierFactory.acervo(List.of(pki.raiz()), List.of(pki.ac())), List.of()));

        assertThat(requests.get()).isZero();
    }
}
