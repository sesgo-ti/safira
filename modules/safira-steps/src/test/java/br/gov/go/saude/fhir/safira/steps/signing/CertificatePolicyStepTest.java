/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.LeafProfile;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

class CertificatePolicyStepTest {

    private static final long NOW = 1790000000L;
    private static TestPki pki;

    @BeforeAll
    static void createPki() {
        pki = TestPki.create();
    }

    private static SigningContext context(TestPki source, long referenceTimestamp) {
        return SigningContext.builder()
                .certificateChain(new X509Certificate[]{source.leafCert, source.caCert})
                .referenceTimestamp(referenceTimestamp)
                .build();
    }

    private static SignatureExceptionCode code(StepResult<SigningContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<SigningContext>) result).code();
    }

    @Test
    void shouldStoreSignerIdentity() {
        StepResult<SigningContext> result = new CertificatePolicyStep(TestConfigs.policy(pki)).execute(context(pki, NOW));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getAttribute(CertificatePolicyStep.SIGNER_IDENTITY_KEY, SignerIdentity.class))
                .contains(new SignerIdentity(CertificateType.A3, SignerIdentity.CPF_SYSTEM, TestPki.TEST_CPF));
    }

    @Test
    void shouldFailWhenLeafNotInAllowlist() {
        TestPki a1 = TestPki.create(LeafProfile.a3().withPolicyOid("2.16.76.1.2.1.1"));

        assertThat(code(new CertificatePolicyStep(TestConfigs.policy(a1)).execute(context(a1, NOW))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldFailWhenReferenceTimestampAfterLeafExpiry() {
        assertThat(code(new CertificatePolicyStep(TestConfigs.policy(pki)).execute(context(pki, TestPki.CERT_END + 1))))
                .isEqualTo(SignatureExceptionCode.CERT_EXPIRED);
    }

    @Test
    void shouldFailWhenChainIsIncomplete() {
        SigningContext context = SigningContext.builder()
                .certificateChain(new X509Certificate[]{pki.leafCert})
                .referenceTimestamp(NOW)
                .build();

        assertThat(code(new CertificatePolicyStep(TestConfigs.policy(pki)).execute(context)))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }
}
