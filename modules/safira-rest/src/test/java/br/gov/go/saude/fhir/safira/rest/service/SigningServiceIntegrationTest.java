/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

import java.security.cert.PKIXReason;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.when;

/** Integração do {@link SigningService} com a pipeline 0.2.0 e o contexto Spring completo. */
@SpringBootTest
class SigningServiceIntegrationTest {

    @MockitoBean
    PkixCertificateValidator pkixCertificateValidator;

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

    @Test
    void shouldReturnSigningResultWhenChainIsTrusted() throws Exception {
        when(pkixCertificateValidator.validate(any(), anyCollection())).thenReturn(new ValidationResult.Valid(
                List.of(JadesSigningSystemTest.PKI.leafCert), JadesSigningSystemTest.PKI.caCert, List.of()));

        PipelineResult<?> result = signingService.sign(body());

        assertThat(result.getValue()).isInstanceOf(SigningResult.class);
    }

    @Test
    void shouldReturnCertNotIcpBrasilWhenChainIsOutsideTheTrustStore() throws Exception {
        when(pkixCertificateValidator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Untrusted(PKIXReason.NO_TRUST_ANCHOR, "sem âncora"));

        assertThat(code(signingService.sign(body()))).isEqualTo("CERT.NOT-ICP-BRASIL");
    }

    @Test
    void shouldReturnTrustStoreEmptyWhenCatalogIsNotLoaded() throws Exception {
        when(pkixCertificateValidator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.TrustStoreUnavailable());

        assertThat(code(signingService.sign(body()))).isEqualTo("CONFIG.TRUST-STORE-EMPTY");
    }

    @Test
    void shouldReturnFormatErrorForInvalidJson() {
        assertThat(code(signingService.sign("{"))).isEqualTo("FORMAT.BUNDLE-MALFORMED");
    }
}
