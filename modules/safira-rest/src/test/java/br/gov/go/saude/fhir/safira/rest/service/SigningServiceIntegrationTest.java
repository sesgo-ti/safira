/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/** Integração do {@link SigningService} com a pipeline 0.2.0 e o contexto Spring completo. */
@SpringBootTest
@Import(OfflineRevocationConfig.class)
class SigningServiceIntegrationTest {

    @MockitoBean
    FonteDeConfianca fonteDeConfianca;

    @Autowired
    SigningService signingService;

    @DynamicPropertySource
    static void policy(DynamicPropertyRegistry registry) {
        JadesSigningSystemTest.policy(registry);
    }

    private static String body() throws Exception {
        return JadesSigningSystemTest.signingBody(JadesSigningSystemTest.POLICY_URI, Instant.now().getEpochSecond());
    }

    private static String code(PipelineResult<?> result) {
        return result.getExceptionDetails().issue().getFirst().details().coding().getFirst().code();
    }

    @BeforeEach
    void resetRevocation() {
        OfflineRevocationConfig.reset();
    }

    private void acervo(X509Certificate root) {
        when(fonteDeConfianca.atual()).thenReturn(AcervoDeTeste.com(root));
    }

    @Test
    void shouldReturnSigningResultWhenChainIsTrusted() throws Exception {
        acervo(JadesSigningSystemTest.PKI.caCert);

        PipelineResult<?> result = signingService.sign(body());

        assertThat(result.getValue()).isInstanceOf(SigningResult.class);
    }

    @Test
    void shouldReturnCertNotIcpBrasilWhenChainIsOutsideTheTrustStore() throws Exception {
        acervo(TestPki.create().caCert);

        assertThat(code(signingService.sign(body()))).isEqualTo("CERT.NOT-ICP-BRASIL");
    }

    @Test
    void shouldReturnCertRevokedWhenSignerIsRevoked() throws Exception {
        acervo(JadesSigningSystemTest.PKI.caCert);
        OfflineRevocationConfig.responder = JadesSigningSystemTest.PKI::ocspRevokedFor;

        assertThat(code(signingService.sign(body()))).isEqualTo("CERT.REVOKED");
    }

    @Test
    void shouldReturnTrustStoreEmptyWhenCatalogIsNotLoaded() throws Exception {
        when(fonteDeConfianca.atual()).thenReturn(Optional.empty());

        assertThat(code(signingService.sign(body()))).isEqualTo("CONFIG.TRUST-STORE-EMPTY");
    }

    @Test
    void shouldReturnFormatErrorForInvalidJson() {
        assertThat(code(signingService.sign("{"))).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }
}
