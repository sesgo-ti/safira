/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class IcpBrasilCertificateVerifiersTest {

    private static TestPki pki;
    private static TestPki other;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        other = TestPki.create();
    }

    private static TrustMaterial acervo(TestPki source) {
        return TrustMaterial.of(List.of(source.caCert, source.tsaCert, source.leafCert));
    }

    private static IcpBrasilCertificateVerifiers verifiers(AtomicReference<TrustMaterial> material) {
        return new IcpBrasilCertificateVerifiers(() -> Optional.ofNullable(material.get()),
                CertificateVerifierFactory.offline(null, null));
    }

    @Test
    void shouldTrustOnlyAcervoRootsWhenAcervoIsAvailable() {
        CommonCertificateVerifier verifier = verifiers(new AtomicReference<>(acervo(pki))).current().orElseThrow();

        assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(pki.caCert));
    }

    @Test
    void shouldOfferAcervoCasAsAdjunctWhenAcervoIsAvailable() {
        CommonCertificateVerifier verifier = verifiers(new AtomicReference<>(acervo(pki))).current().orElseThrow();

        assertThat(verifier.getAdjunctCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.tsaCert), new CertificateToken(pki.leafCert));
    }

    @Test
    void shouldAddExtraAnchorsWhenGivenPerCall() {
        CommonCertificateVerifier verifier = verifiers(new AtomicReference<>(acervo(pki)))
                .current(List.of(other.caCert)).orElseThrow();

        assertThat(verifier.getTrustedCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.caCert), new CertificateToken(other.caCert));
    }

    @Test
    void shouldReturnEmptyWhenAcervoIsUnavailable() {
        assertThat(verifiers(new AtomicReference<>()).current()).isEmpty();
    }

    @Test
    void shouldReuseDssSourcesWhenGenerationIsUnchanged() {
        IcpBrasilCertificateVerifiers verifiers = verifiers(new AtomicReference<>(acervo(pki)));

        assertThat(verifiers.current().orElseThrow().getTrustedCertSources().getSources().getFirst())
                .isSameAs(verifiers.current().orElseThrow().getTrustedCertSources().getSources().getFirst());
    }

    @Test
    void shouldFollowNewGenerationWhenAcervoChanges() {
        AtomicReference<TrustMaterial> material = new AtomicReference<>(acervo(pki));
        IcpBrasilCertificateVerifiers verifiers = verifiers(material);
        verifiers.current();
        material.set(acervo(other));

        assertThat(verifiers.current().orElseThrow().getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(other.caCert));
    }
}
