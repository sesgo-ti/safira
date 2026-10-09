/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust.icpbrasil;

import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class FonteDeConfiancaIcpBrasilTest {

    private static TestPki pki;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
    }

    private static TrustMaterial material() {
        return TrustMaterial.of(List.of(pki.caCert, pki.tsaCert, pki.leafCert));
    }

    private static FonteDeConfiancaIcpBrasil fonte(AtomicReference<TrustMaterial> material) {
        return new FonteDeConfiancaIcpBrasil(() -> Optional.ofNullable(material.get()));
    }

    @Test
    void shouldExposeAnchorsAsRaizesAndIntermediatesAsIntermediarias() {
        AcervoDeConfianca acervo = fonte(new AtomicReference<>(material())).atual().orElseThrow();

        assertThat(acervo.raizes()).containsExactly(pki.caCert);
        assertThat(acervo.intermediarias()).containsExactlyInAnyOrder(pki.tsaCert, pki.leafCert);
    }

    @Test
    void shouldKeepGenerationWhileTrustMaterialIsSameInstance() {
        FonteDeConfiancaIcpBrasil fonte = fonte(new AtomicReference<>(material()));
        AcervoDeConfianca primeiro = fonte.atual().orElseThrow();
        AcervoDeConfianca segundo = fonte.atual().orElseThrow();

        assertThat(segundo.geracao()).isEqualTo(primeiro.geracao());
        assertThat(segundo).isSameAs(primeiro);
    }

    @Test
    void shouldChangeGenerationWhenTrustMaterialInstanceChanges() {
        AtomicReference<TrustMaterial> material = new AtomicReference<>(material());
        FonteDeConfiancaIcpBrasil fonte = fonte(material);
        String primeira = fonte.atual().orElseThrow().geracao();
        material.set(material());

        assertThat(fonte.atual().orElseThrow().geracao()).isNotEqualTo(primeira);
    }

    @Test
    void shouldReturnEmptyWhenLibHasNoTrustMaterial() {
        assertThat(fonte(new AtomicReference<>()).atual()).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenLibFails() {
        FonteDeConfiancaIcpBrasil fonte = new FonteDeConfiancaIcpBrasil(() -> {
            throw new IllegalStateException("cache corrompido");
        });

        assertThat(fonte.atual()).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenIntermediatesAreUnreadable() throws Exception {
        CertStore intermediates = mock(CertStore.class);
        when(intermediates.getCertificates(any())).thenThrow(new CertStoreException("ilegível"));
        TrustMaterial material = mock(TrustMaterial.class);
        when(material.anchors()).thenReturn(material().anchors());
        when(material.intermediates()).thenReturn(intermediates);

        assertThat(fonte(new AtomicReference<>(material)).atual()).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenTrustMaterialHasNoAnchors() {
        assertThat(fonte(new AtomicReference<>(TrustMaterial.of(List.of(pki.leafCert)))).atual()).isEmpty();
    }

    @Test
    void shouldLogErrorOnlyOnFirstFailureOfSameTrustMaterial() {
        ListAppender<ILoggingEvent> eventos = capturarLog();
        FonteDeConfiancaIcpBrasil fonte = fonte(new AtomicReference<>(TrustMaterial.of(List.of(pki.leafCert))));

        fonte.atual();
        fonte.atual();
        fonte.atual();

        assertThat(eventos.list).extracting(ILoggingEvent::getLevel)
                .containsExactly(Level.ERROR, Level.DEBUG, Level.DEBUG);
    }

    @Test
    void shouldLogErrorAgainWhenFailureReturnsAfterRecovery() {
        ListAppender<ILoggingEvent> eventos = capturarLog();
        TrustMaterial semRaizes = TrustMaterial.of(List.of(pki.leafCert));
        AtomicReference<TrustMaterial> material = new AtomicReference<>(semRaizes);
        FonteDeConfiancaIcpBrasil fonte = fonte(material);

        fonte.atual();
        material.set(material());
        fonte.atual();
        material.set(semRaizes);
        fonte.atual();

        assertThat(eventos.list).extracting(ILoggingEvent::getLevel).containsExactly(Level.ERROR, Level.ERROR);
    }

    private static ListAppender<ILoggingEvent> capturarLog() {
        Logger logger = (Logger) LoggerFactory.getLogger(FonteDeConfiancaIcpBrasil.class);
        logger.detachAndStopAllAppenders();
        logger.setAdditive(false);
        logger.setLevel(Level.DEBUG);
        ListAppender<ILoggingEvent> eventos = new ListAppender<>();
        eventos.start();
        logger.addAppender(eventos);
        return eventos;
    }

    @AfterEach
    void restaurarLog() {
        Logger logger = (Logger) LoggerFactory.getLogger(FonteDeConfiancaIcpBrasil.class);
        logger.detachAndStopAllAppenders();
        logger.setAdditive(true);
        logger.setLevel(null);
    }
}
