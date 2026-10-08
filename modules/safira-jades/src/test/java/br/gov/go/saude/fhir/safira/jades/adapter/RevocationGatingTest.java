/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A rede do verificador só é usada para revogação de cadeias que terminam numa âncora: o
 * certificado da TSA fake traz OCSP no AIA (127.0.0.1), consultado apenas quando sua raiz é confiável.
 */
class RevocationGatingTest {

    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static String bt;

    @BeforeAll
    static void sign() throws Exception {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        JadesSigningService signing = new JadesSigningService();
        JadesSigningSession session = signing.newSession(new JadesSigningService.Request(pki.chain(),
                MessageDigest.getInstance("SHA-256").digest("x".getBytes(StandardCharsets.UTF_8)),
                Instant.now().getEpochSecond(), "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0"));
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(pki.leafKeys.getPrivate());
        signer.update(signing.dataToSign(session));
        bt = new JadesExtensionService().extendToBaselineT(signing.sign(session, signer.sign()),
                TspSources.online(tsa.url(), 10, TestPki.TSA_POLICY_OID));
    }

    @AfterAll
    static void stop() {
        tsa.close();
    }

    private static List<InetAddress> validate(TestPki trusted) {
        List<InetAddress> contacted = new CopyOnWriteArrayList<>();
        CertificateVerifierFactory factory = CertificateVerifierFactory.online(5, 5,
                (host, address) -> contacted.add(address), Set.of(URI.create(tsa.url()).getPort()));
        new JadesValidationService().validate(bt,
                factory.create(CertificateVerifierFactory.acervo(List.of(trusted.caCert), List.of()), List.of()));
        return contacted;
    }

    @Test
    void shouldFetchRevocationWhenChainEndsInTrustedRoot() {
        assertThat(validate(pki)).isNotEmpty();
    }

    @Test
    void shouldNotOpenAnyConnectionWhenChainIsUntrusted() {
        assertThat(validate(TestPki.create())).isEmpty();
    }
}
