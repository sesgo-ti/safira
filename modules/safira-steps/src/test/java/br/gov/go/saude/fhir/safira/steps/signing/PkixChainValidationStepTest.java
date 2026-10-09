/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.testkit.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.PerfilSignatario;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.support.FonteDeTeste;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
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

    private static PkiIcpSimulada pki;
    private static FonteDeConfianca acervo;

    @BeforeAll
    static void createPki() {
        pki = PkiIcpSimulada.criar();
        acervo = FonteDeTeste.com(pki.raiz(), pki.ac());
    }

    private static PkixChainValidationStep step(FonteDeConfianca trust, RevocationSource<OCSP> ocsp) {
        return new PkixChainValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(ocsp, null)), allowlist(pki));
    }

    private static SafiraPolicyProperties allowlist(PkiIcpSimulada issuer) {
        return new SafiraPolicyProperties(List.of(new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3,
                issuer.emissorSha256())), null, null);
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

    private static String diagnostics(StepResult<SigningContext> result) {
        return ((StepResult.Failure<SigningContext>) result).diagnostics();
    }

    private static SignatureExceptionCode code(StepResult<SigningContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<SigningContext>) result).code();
    }

    @Test
    void shouldStoreChainEndingInAcervoRootWhenOnlyLeafIsSupplied() throws Exception {
        StepResult<SigningContext> result = step(pki.fonteOcsp()).execute(context(List.of(b64(pki.signatario()))));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.cadeia().toArray(X509Certificate[]::new));
    }

    @Test
    void shouldCaptureAcervoSnapshotInContext() throws Exception {
        StepResult<SigningContext> result = step(pki.fonteOcsp()).execute(context(List.of(b64(pki.signatario()))));

        assertThat(result.context().getAttribute(SigningKeys.ACERVO, AcervoDeConfianca.class)).isPresent();
    }

    @Test
    void shouldStoreSameChainWhenRootIsAlsoSupplied() throws Exception {
        StepResult<SigningContext> result = step(pki.fonteOcsp())
                .execute(context(List.of(b64(pki.signatario()), b64(pki.ac()), b64(pki.raiz()))));

        assertThat(result.context().getCertificateChain().orElseThrow()).containsExactly(pki.cadeia().toArray(X509Certificate[]::new));
    }

    @Test
    void shouldRejectLeafWhenIssuingCaIsNeitherSuppliedNorInAcervo() throws Exception {
        FonteDeConfianca soRaiz = FonteDeTeste.com(pki.raiz());

        StepResult<SigningContext> result = step(soRaiz, pki.fonteOcsp()).execute(context(List.of(b64(pki.signatario()))));

        // o DSS não monta caminho até a raiz sem a AC (NO_CERTIFICATE_CHAIN_FOUND)
        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectRevokedSigner() throws Exception {
        RevocationSource<OCSP> revoked = EvidenceRevocationSources.ocspPorCertificado(pki.respostasComSignatarioRevogado());

        StepResult<SigningContext> result = step(revoked).execute(context(List.of(b64(pki.signatario()))));

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
        // a folha (REVOKED_NO_POE), não a AC (REVOKED_CA_NO_POE, mesmo código)
        assertThat(diagnostics(result)).contains("/REVOKED_NO_POE");
    }

    @Test
    void shouldRejectWhenNoRevocationIsReachable() throws Exception {
        StepResult<SigningContext> result = step(EvidenceRevocationSources.ocspPorCertificado(
                pki.respostasSemRevogacaoDoSignatario())).execute(context(List.of(b64(pki.signatario()))));

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN);
        // só a folha sem revogação: a AC sem resposta acrescentaria "revocation issuer" (mesmo código)
        assertThat(diagnostics(result)).contains("No revocation data found for the certificate").doesNotContain("revocation issuer");
    }

    @Test
    void shouldRejectWhenIssuingCaIsRevoked() throws Exception {
        RevocationSource<OCSP> caRevoked = EvidenceRevocationSources.ocspPorCertificado(pki.respostasComAcRevogada());

        StepResult<SigningContext> result = step(caRevoked).execute(context(List.of(b64(pki.signatario()))));

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
        assertThat(diagnostics(result)).contains("/REVOKED_CA_NO_POE");
    }

    @Test
    void shouldRejectWhenIssuingCaRevocationIsUnavailable() throws Exception {
        StepResult<SigningContext> result = step(EvidenceRevocationSources.ocspPorCertificado(
                pki.respostasSemRevogacaoDaAc())).execute(context(List.of(b64(pki.signatario()))));

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN);
        assertThat(diagnostics(result)).contains("revocation issuer");
    }

    @Test
    void shouldRejectSignerWhenRootIsOutsideAcervo() throws Exception {
        FonteDeConfianca other = FonteDeTeste.com(PkiIcpSimulada.criar().raiz());

        assertThat(code(step(other, pki.fonteOcsp()).execute(context(List.of(b64(pki.signatario()), b64(pki.ac()))))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldFailClosedWhenAcervoIsUnavailable() throws Exception {
        assertThat(code(step(Optional::empty, pki.fonteOcsp()).execute(context(List.of(b64(pki.signatario()))))))
                .isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldRejectEmptyChain() {
        assertThat(code(step(pki.fonteOcsp()).execute(context(List.of()))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE);
    }

    @Test
    void shouldRejectNonBase64Certificate() {
        assertThat(code(step(pki.fonteOcsp()).execute(context(List.of("não é base64")))))
                .isEqualTo(SignatureExceptionCode.FORMAT_BASE64_INVALID);
    }

    @Test
    void shouldRejectNonDerCertificate() {
        assertThat(code(step(pki.fonteOcsp()).execute(context(List.of("AAAA")))))
                .isEqualTo(SignatureExceptionCode.CERT_INVALID_FORMAT);
    }

    @Test
    void shouldRejectWithNotIcpBrasilWhenLeafPolicyIsOutsideAcceptedList() throws Exception {
        PkiIcpSimulada a1 = PkiIcpSimulada.criar(PerfilSignatario.a3().comPolitica("2.16.76.1.2.1.1"));
        FonteDeConfianca trust = FonteDeTeste.com(a1.raiz(), a1.ac());

        assertThat(code(step(trust, a1.fonteOcsp()).execute(context(List.of(b64(a1.signatario()))))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldReportPolicyBeforeRevocationWhenLeafPolicyIsOutsideAcceptedList() throws Exception {
        PkiIcpSimulada a1 = PkiIcpSimulada.criar(PerfilSignatario.a3().comPolitica("2.16.76.1.2.1.1"));
        FonteDeConfianca trust = FonteDeTeste.com(a1.raiz(), a1.ac());

        assertThat(code(step(trust, EvidenceRevocationSources.ocspPorCertificado(a1.respostasComSignatarioRevogado())).execute(context(List.of(b64(a1.signatario()))))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldFailClosedWhenAllowlistIsEmpty() throws Exception {
        PkixChainValidationStep step = new PkixChainValidationStep(new VerificadoresDss(acervo,
                CertificateVerifierFactory.offline(pki.fonteOcsp(), null)), new SafiraPolicyProperties(List.of(), null, null));

        assertThat(code(step.execute(context(List.of(b64(pki.signatario()))))))
                .isEqualTo(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }
}
