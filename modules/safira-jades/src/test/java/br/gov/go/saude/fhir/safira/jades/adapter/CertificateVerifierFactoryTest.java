/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.testkit.CertificadosIcpBrasilReais;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.service.crl.OnlineCRLSource;
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateVerifierFactoryTest {

    private static PkiIcpSimulada pki;
    private static PkiIcpSimulada other;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        other = PkiIcpSimulada.criar();
    }

    private static CertificateVerifierFactory.Acervo acervo() {
        return CertificateVerifierFactory.acervo(List.of(pki.raiz()), List.of(pki.tsa()));
    }

    @Test
    void shouldTrustOnlyRootsWhenNoExtraAnchorIsGiven() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(verifier.getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.raiz()));
    }

    @Test
    void shouldOfferIntermediatesAsAdjunctCertificatesWhenAcervoIsBuilt() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(verifier.getAdjunctCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.tsa()));
        assertThat(verifier.getTrustedCertSources().isTrusted(new CertificateToken(pki.tsa()))).isFalse();
    }

    @Test
    void shouldAddExtraAnchorsAsTrustedWhenGivenPerCall() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null)
                .create(acervo(), List.of(other.raiz()));

        assertThat(verifier.getTrustedCertSources().getCertificates())
                .containsExactlyInAnyOrder(new CertificateToken(pki.raiz()), new CertificateToken(other.raiz()));
    }

    @Test
    void shouldNotLeakExtraAnchorsToLaterVerifiersWhenAcervoIsReused() {
        CertificateVerifierFactory factory = CertificateVerifierFactory.offline(null, null);
        CertificateVerifierFactory.Acervo shared = acervo();
        factory.create(shared, List.of(other.raiz()));

        assertThat(factory.create(shared, List.of()).getTrustedCertSources().getCertificates())
                .containsExactly(new CertificateToken(pki.raiz()));
    }

    @Test
    void shouldGiveEachVerifierItsOwnAdjunctSourceWhenAcervoIsReused() {
        CertificateVerifierFactory factory = CertificateVerifierFactory.offline(null, null);
        CertificateVerifierFactory.Acervo shared = acervo();

        assertThat(factory.create(shared, List.of()).getAdjunctCertSources().getSources().getFirst())
                .isNotSameAs(factory.create(shared, List.of()).getAdjunctCertSources().getSources().getFirst());
    }

    @Test
    void shouldGiveEachVerifierItsOwnCaTokensWhenAcervoIsReused() {
        CertificateVerifierFactory factory = CertificateVerifierFactory.offline(null, null);
        CertificateVerifierFactory.Acervo shared = acervo();

        assertThat(factory.create(shared, List.of()).getAdjunctCertSources().getCertificates().getFirst())
                .isNotSameAs(factory.create(shared, List.of()).getAdjunctCertSources().getCertificates().getFirst());
    }

    @Test
    void shouldUseDssOnlineRevocationWithoutAiaWhenOnline() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.online(7, 9, (host, address) -> { }).create(acervo(), List.of());

        assertThat(verifier.getOcspSource()).isInstanceOf(OnlineOCSPSource.class);
        assertThat(verifier.getCrlSource()).isInstanceOf(OnlineCRLSource.class);
        assertThat(verifier.getAIASource()).isNull();
        assertThat(verifier.isCheckRevocationForUntrustedChains()).isFalse();
    }

    @Test
    void shouldApplyConfiguredTimeoutsWhenOnline() {
        List<RestrictedDataLoader> loaders = CertificateVerifierFactory.online(7, 9, (host, address) -> { }).dataLoaders();

        assertThat(loaders).hasSize(2);
        assertThat(loaders.get(0).getTimeoutConnection()).isEqualTo(7000);
        assertThat(loaders.get(0).getTimeoutResponse()).isEqualTo(7000);
        assertThat(loaders.get(1).getTimeoutConnection()).isEqualTo(9000);
        assertThat(loaders.get(1).getTimeoutResponse()).isEqualTo(9000);
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

    @Test
    void shouldIgnoreCertificatesUnsupportedByDssWhenAcervoIsBuilt() {
        X509Certificate v7 = CertificadosIcpBrasilReais.raizV7();
        Logger logger = (Logger) LoggerFactory.getLogger(CertificateVerifierFactory.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        try {
            CertificateVerifierFactory.Acervo acervo = CertificateVerifierFactory.acervo(List.of(v7, pki.raiz()),
                    List.of(v7, pki.ac()));
            CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo, List.of());

            assertThat(acervo.utilizavel()).isTrue();
            assertThat(verifier.getTrustedCertSources().getCertificates()).containsExactly(new CertificateToken(pki.raiz()));
            assertThat(verifier.getAdjunctCertSources().getCertificates()).containsExactly(new CertificateToken(pki.ac()));
            assertThat(new CertificateValidationService().validate(pki.signatario(), List.of(), verifier)
                    .getDiagnosticData().getUsedCertificateById(new CertificateToken(pki.signatario()).getDSSIdAsString())
                    .isTrustedChain()).isTrue();
            assertThat(appender.list)
                    .filteredOn(evento -> evento.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .hasSize(2)
                    .allSatisfy(mensagem -> assertThat(mensagem)
                            .contains("Autoridade Certificadora Raiz Brasileira v7")
                            .contains("5657E70580EB678983F3ED7DFCE091D84CAE6549389A47FCCDA8D0E4DC2CF576"));
        } finally {
            logger.detachAppender(appender);
        }
    }

    @Test
    void shouldNotBeUsableWhenNoRootIsSupportedByDss() {
        CertificateVerifierFactory.Acervo acervo = CertificateVerifierFactory.acervo(
                List.of(CertificadosIcpBrasilReais.raizV7()), List.of(pki.ac()));

        assertThat(acervo.utilizavel()).isFalse();
    }

    @Test
    void shouldIgnoreCandidatesUnsupportedByDssWhenValidatingCertificate() {
        CommonCertificateVerifier verifier = CertificateVerifierFactory.offline(null, null).create(acervo(), List.of());

        assertThat(new CertificateValidationService()
                .validate(pki.signatario(), List.of(CertificadosIcpBrasilReais.raizV7(), pki.ac()), verifier)
                .getDiagnosticData().getUsedCertificateById(new CertificateToken(pki.signatario()).getDSSIdAsString())
                .isTrustedChain()).isTrue();
    }

    @Test
    void shouldReportRepresentabilityWhenCertificateUsesUnsupportedAlgorithm() {
        assertThat(CertificateVerifierFactory.token(CertificadosIcpBrasilReais.raizV7())).isEmpty();
        assertThat(CertificateVerifierFactory.token(pki.raiz())).contains(new CertificateToken(pki.raiz()));
    }
}
