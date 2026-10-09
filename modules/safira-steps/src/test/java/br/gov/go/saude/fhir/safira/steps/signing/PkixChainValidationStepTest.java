/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.trust.icpbrasil.FonteDeConfiancaIcpBrasil;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/** Passo {@code pkix-chain-validation} sobre o verificador do DSS offline (PKI de teste). */
class PkixChainValidationStepTest {

    private static TestPki pki;
    private static TrustMaterialSource acervo;

    @BeforeAll
    static void createPki() {
        pki = TestPki.create();
        acervo = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert)));
    }

    private static PkixChainValidationStep step(TrustMaterialSource trust, RevocationSource<OCSP> ocsp) {
        return new PkixChainValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
                CertificateVerifierFactory.offline(ocsp, null)));
    }

    private static PkixChainValidationStep step(RevocationSource<OCSP> ocsp) {
        return step(acervo, ocsp);
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
    void shouldStoreChainEndingInAcervoRootWhenOnlyLeafIsSupplied() throws Exception {
        StepResult<SigningContext> result = step(pki.ocspGoodSource()).execute(context(List.of(b64(pki.leafCert))));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.leafCert, pki.caCert);
    }

    @Test
    void shouldCaptureAcervoSnapshotInContext() throws Exception {
        StepResult<SigningContext> result = step(pki.ocspGoodSource()).execute(context(List.of(b64(pki.leafCert))));

        assertThat(result.context().getAttribute(SigningKeys.ACERVO, AcervoDeConfianca.class)).isPresent();
    }

    @Test
    void shouldStoreSameChainWhenRootIsAlsoSupplied() throws Exception {
        StepResult<SigningContext> result = step(pki.ocspGoodSource())
                .execute(context(List.of(b64(pki.leafCert), b64(pki.caCert))));

        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.leafCert, pki.caCert);
    }

    @Test
    void shouldRejectRevokedSigner() throws Exception {
        RevocationSource<OCSP> revoked = TestPki.ocspSource(pki::ocspRevokedFor);

        assertThat(code(step(revoked).execute(context(List.of(b64(pki.leafCert))))))
                .isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldRejectWhenNoRevocationIsReachable() throws Exception {
        assertThat(code(step(TestPki.ocspSource(certificate -> null)).execute(context(List.of(b64(pki.leafCert))))))
                .isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN);
    }

    @Test
    void shouldRejectSignerWhenRootIsOutsideAcervo() throws Exception {
        TrustMaterialSource other = () -> Optional.of(TrustMaterial.of(List.of(TestPki.create().caCert)));

        assertThat(code(step(other, pki.ocspGoodSource()).execute(context(List.of(b64(pki.leafCert), b64(pki.caCert))))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldFailClosedWhenAcervoIsUnavailable() throws Exception {
        assertThat(code(step(Optional::empty, pki.ocspGoodSource()).execute(context(List.of(b64(pki.leafCert))))))
                .isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldRejectEmptyChain() {
        assertThat(code(step(pki.ocspGoodSource()).execute(context(List.of()))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    @Test
    void shouldRejectNonBase64Certificate() {
        assertThat(code(step(pki.ocspGoodSource()).execute(context(List.of("não é base64")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldRejectNonDerCertificate() {
        assertThat(code(step(pki.ocspGoodSource()).execute(context(List.of("AAAA")))))
                .isEqualTo(SignatureExceptionCode.CERT_INVALID_FORMAT);
    }
}
