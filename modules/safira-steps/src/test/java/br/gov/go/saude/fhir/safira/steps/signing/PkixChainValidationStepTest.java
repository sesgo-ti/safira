/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.PKIXReason;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class PkixChainValidationStepTest {

    private static TestPki pki;

    @BeforeAll
    static void createPki() {
        pki = TestPki.create();
    }

    private static String b64(X509Certificate certificate) throws Exception {
        return Base64.getEncoder().encodeToString(certificate.getEncoded());
    }

    private static SigningContext context(List<String> chain) {
        return SigningContext.builder().rawCertificateChain(chain).build();
    }

    private static SignatureExceptionCode code(StepResult<SigningContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<SigningContext>) result).code();
    }

    @Test
    void shouldStoreChainWithAnchorWhenValid() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        RevocationEvidence evidence = new RevocationEvidence.OcspResponse(pki.ocspGoodFor(pki.leafCert));
        when(validator.validate(eq(pki.leafCert), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of(evidence)));

        StepResult<SigningContext> result = new PkixChainValidationStep(validator)
                .execute(context(List.of(b64(pki.leafCert))));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.leafCert, pki.caCert);
        assertThat(result.context().getAttribute(PkixChainValidationStep.REVOCATION_EVIDENCE_KEY, List.class))
                .contains(List.of(evidence));
    }

    @Test
    void shouldPassSuppliedIntermediatesAsCandidates() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(eq(pki.leafCert), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of()));

        new PkixChainValidationStep(validator).execute(context(List.of(b64(pki.leafCert), b64(pki.caCert))));

        verify(validator).validate(pki.leafCert, List.of(pki.caCert));
    }

    @Test
    void shouldMapUntrustedResult() throws Exception {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Untrusted(PKIXReason.NO_TRUST_ANCHOR, "sem âncora"));

        assertThat(code(new PkixChainValidationStep(validator).execute(context(List.of(b64(pki.leafCert))))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectEmptyChain() {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);

        assertThat(code(new PkixChainValidationStep(validator).execute(context(List.of()))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
        verify(validator, never()).validate(any(), anyCollection());
    }

    @Test
    void shouldRejectNonBase64Certificate() {
        assertThat(code(new PkixChainValidationStep(mock(PkixCertificateValidator.class))
                .execute(context(List.of("não é base64")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldRejectNonDerCertificate() {
        assertThat(code(new PkixChainValidationStep(mock(PkixCertificateValidator.class))
                .execute(context(List.of("AAAA")))))
                .isEqualTo(SignatureExceptionCode.CERT_INVALID_FORMAT);
    }
}
