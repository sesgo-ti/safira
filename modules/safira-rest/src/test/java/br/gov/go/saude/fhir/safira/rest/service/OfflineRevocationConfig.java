/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.security.cert.X509Certificate;
import java.util.function.Function;

/**
 * Substitui as fontes online do verificador do DSS por OCSP offline da PKI de teste; cada teste
 * pode trocar o {@link #responder} (nulo = sem revogação disponível para o certificado).
 */
@TestConfiguration(proxyBeanMethods = false)
public class OfflineRevocationConfig {

    static volatile Function<X509Certificate, byte[]> responder = JadesSigningSystemTest.PKI::ocspGoodFor;

    /** Volta a responder {@code GOOD} para qualquer certificado da PKI de teste. */
    static void reset() {
        responder = JadesSigningSystemTest.PKI::ocspGoodFor;
    }

    @Bean
    CertificateVerifierFactory offlineCertificateVerifierFactory() {
        return CertificateVerifierFactory.offline(TestPki.ocspSource(certificate -> responder.apply(certificate)), null);
    }
}
