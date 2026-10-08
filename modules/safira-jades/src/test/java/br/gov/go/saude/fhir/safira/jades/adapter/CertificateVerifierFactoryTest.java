/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateVerifierFactoryTest {

    private static TestPki pki;
    private static TestPki other;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        other = TestPki.create();
    }

    private static CertificateVerifierFactory.Acervo acervo() {
        return CertificateVerifierFactory.acervo(List.of(pki.caCert), List.of(pki.tsaCert));
    }

    @Test
    void shouldTrustOnlyRootsWhenNoExtraAnchorIsGiven() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(verifier.getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.caCert));
    }

    @Test
    void shouldOfferIntermediatesAsAdjunctCertificatesWhenAcervoIsBuilt() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(verifier.getAdjunctCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.tsaCert));
        assertThat(verifier.getTrustedCertSources().isTrusted(new CertificateToken(pki.tsaCert))).isFalse();
    }

    @Test
    void shouldAddExtraAnchorsAsTrustedWhenGivenPerCall() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null)
                .create(acervo(), List.of(other.caCert));

        assertThat(verifier.getTrustedCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.caCert), new CertificateToken(other.caCert));
    }

    @Test
    void shouldNotLeakExtraAnchorsToLaterVerifiersWhenAcervoIsReused() {
        CertificateVerifierFactory factory = CertificateVerifierFactory.offline(null, null);
        CertificateVerifierFactory.Acervo shared = acervo();
        factory.create(shared, List.of(other.caCert));

        assertThat(factory.create(shared, List.of()).getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.caCert));
    }

    @Test
    void shouldUseDssOnlineSourcesWhenOnline() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.online(7, 9, (host, address) -> { }).create(acervo(), List.of());

        assertThat(verifier.getOcspSource()).isInstanceOf(OnlineOCSPSource.class);
        assertThat(verifier.getCrlSource()).isInstanceOf(OnlineCRLSource.class);
        assertThat(verifier.getAIASource()).isInstanceOf(DefaultAIASource.class);
    }

    @Test
    void shouldApplyConfiguredTimeoutsWhenOnline() {
        List<RestrictedDataLoader> loaders = CertificateVerifierFactory.online(7, 9, (host, address) -> { }).dataLoaders();

        assertThat(loaders).hasSize(3);
        assertThat(loaders.get(0).getTimeoutConnection()).isEqualTo(7000);
        assertThat(loaders.get(0).getTimeoutResponse()).isEqualTo(7000);
        assertThat(loaders.get(1).getTimeoutConnection()).isEqualTo(9000);
        assertThat(loaders.get(1).getTimeoutResponse()).isEqualTo(9000);
        assertThat(loaders.get(2).getTimeoutConnection()).isEqualTo(9000);
        assertThat(loaders).allSatisfy(loader -> {
            assertThat(loader.isRedirectsEnabled()).isFalse();
            assertThat(loader.getMaxResponseBytes()).isEqualTo(CertificateVerifierFactory.MAX_RESPONSE_BYTES);
        });
        assertThat(loaders.get(0).getContentType()).isEqualTo("application/ocsp-request");
    }

    @Test
    void shouldNotUseAiaWhenOffline() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(verifier.getAIASource()).isNull();
        assertThat(verifier.getOcspSource()).isNull();
        assertThat(verifier.getCrlSource()).isNull();
    }
}
