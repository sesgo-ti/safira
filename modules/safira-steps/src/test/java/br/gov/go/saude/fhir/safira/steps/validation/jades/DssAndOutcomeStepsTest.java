/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.testkit.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.testkit.PerfilSignatario;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.TsaHttpLocal;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TrustStoreRef;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicies;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.support.FonteDeTeste;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Steps {@code dss-validation}, {@code timestamp-validation} e {@code validation-outcome}. */
class DssAndOutcomeStepsTest {

    @TempDir
    static Path tempDir;
    private static PkiIcpSimulada pki;
    private static TsaHttpLocal tsa;
    private static SafiraPolicyProperties policy;
    private static FonteDeConfianca trust;
    private static ValidationContext bb;
    private static ValidationContext bbSemAcervo;
    private static ValidationContext bt;
    private static Instant btTimestampTime;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        tsa = pki.iniciarTsaHttp();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, pki.raiz()));
        trust = FonteDeTeste.com(pki.raiz(), pki.ac());
        ValidationContext signed = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
        bb = structured(signed);
        bbSemAcervo = new JwsStructureStep().execute(new SignatureBindingStep().execute(signed).context()).context();
        btTimestampTime = Instant.now();
        bt = structured(SignedArtifactFixture.validationContext(
                SignedArtifactFixture.sign(pki, policy, Instant.now().getEpochSecond(), tsa)));
    }

    @AfterAll
    static void stop() {
        tsa.close();
    }

    private static ValidationContext structured(ValidationContext context) {
        ValidationContext bound = new SignatureBindingStep().execute(context).context();
        ValidationContext parsed = new JwsStructureStep().execute(bound).context();
        return new SignerCertificateStep(policy, new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(null, null))).execute(SignedArtifactFixture.comAcervo(parsed, trust)).context();
    }

    /** DSS offline: respostas OCSP prontas (sem rede) sobre o acervo informado. */
    private static DssValidationStep step(RevocationSource<OCSP> ocsp) {
        return new DssValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(ocsp, null)), policy);
    }

    /** OCSP GOOD, assinado pelos emissores da PKI de teste, para o titular, a AC e a TSA. */
    private static RevocationSource<OCSP> good() {
        return EvidenceRevocationSources.ocspFromEvidence(
                List.of(pki.ocspBom(pki.signatario()), pki.ocspBom(pki.ac()), pki.ocspBom(tsa.certificado())));
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    @Test
    void shouldAcceptBaselineBThroughDss() {
        assertThat(step(good()).execute(bb).isSuccess()).isTrue();
    }

    @Test
    void shouldAcceptBaselineTThroughDss() {
        assertThat(step(good()).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldReportPolicyComplianceWhenDssRejectsLeafPolicyOutsideAcceptedList() {
        SafiraPolicyProperties seloApenas = new SafiraPolicyProperties(List.of(new AcceptedCertificatePolicy(
                "2.16.76.1.2.201.1", CertificateType.SE_S, pki.emissorSha256())), policy.tsaPolicies(), policy.temporalPolicy());
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(good(), null)), seloApenas);

        assertThat(code(step.execute(bb))).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldFailClosedWhenAllowlistIsEmpty() {
        SafiraPolicyProperties semAllowlist = new SafiraPolicyProperties(List.of(), policy.tsaPolicies(), policy.temporalPolicy());
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(good(), null)), semAllowlist);

        assertThat(code(step.execute(bb))).isEqualTo(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectSignerWithUnknownCriticalExtensionAsChainValidationFailed() {
        StepResult<ValidationContext> result = validateWithLeaf(PerfilSignatario.a3().comExtensaoCriticaDesconhecida());

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
        assertThat(((StepResult.Failure<ValidationContext>) result).diagnostics()).contains("1.3.6.1.4.1.99999.1");
    }

    @Test
    void shouldAcceptSameSignerWithoutUnknownCriticalExtension() {
        assertThat(validateWithLeaf(PerfilSignatario.a3()).isSuccess()).isTrue();
    }

    private static StepResult<ValidationContext> validateWithLeaf(PerfilSignatario profile) {
        PkiIcpSimulada leafPki = PkiIcpSimulada.criar(profile);
        SafiraPolicyProperties leafPolicy = TestConfigs.policy(leafPki,
                TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, leafPki.raiz()));
        FonteDeConfianca leafTrust = FonteDeTeste.com(leafPki.raiz(), leafPki.ac());
        ValidationContext signed = SignedArtifactFixture.validationContext(
                SignedArtifactFixture.signSemVerificarCadeia(leafPki, leafPolicy));
        ValidationContext parsed = new JwsStructureStep().execute(new SignatureBindingStep().execute(signed).context()).context();
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(leafTrust,
                CertificateVerifierFactory.offline(EvidenceRevocationSources.ocspFromEvidence(
                        List.of(leafPki.ocspBom(leafPki.signatario()), leafPki.ocspBom(leafPki.ac()))), null)), leafPolicy);
        return step.execute(SignedArtifactFixture.comAcervo(parsed, leafTrust));
    }

    @Test
    void shouldNotLeakTrustStoreReferenceWhenTsaTrustStoreIsUnreadable() {
        SafiraPolicyProperties broken = TestConfigs.policy(pki, new TsaPolicies("1.0.0", List.of(new TsaPolicy(
                PkiIcpSimulada.POLITICA_TSA, 1L, new TrustStoreRef("file:/segredo-caminho/ausente.pem")))));
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(good(), null)), broken);

        StepResult<ValidationContext> result = step.execute(bt);

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
        assertThat(((StepResult.Failure<ValidationContext>) result).diagnostics()).doesNotContain("segredo-caminho");
    }

    @Test
    void shouldMapMissingRevocationToRevocationCodeWhenNoSourceAnswers() {
        assertThat(code(step(null).execute(bb))).isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN);
    }

    @Test
    void shouldRejectRevokedSignerForBaselineB() {
        RevocationSource<OCSP> revoked = EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspRevogado(pki.signatario()),
                pki.ocspBom(pki.ac())));

        assertThat(code(step(revoked).execute(bb))).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldAcceptBaselineTWhenSignerIsRevokedAfterTimestamp() {
        // granularidade de segundos do OCSP: revogação claramente posterior ao genTime do carimbo
        Date afterTimestamp = Date.from(btTimestampTime.plusSeconds(2));
        RevocationSource<OCSP> revokedLater = EvidenceRevocationSources.ocspFromEvidence(List.of(
                pki.ocspRevogado(pki.signatario(), afterTimestamp), pki.ocspBom(pki.ac()), pki.ocspBom(tsa.certificado())));

        assertThat(step(revokedLater).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectBaselineBWhenSignerIsRevokedNow() {
        RevocationSource<OCSP> revokedNow = EvidenceRevocationSources.ocspFromEvidence(List.of(
                pki.ocspRevogado(pki.signatario(), new Date()), pki.ocspBom(pki.ac())));

        assertThat(code(step(revokedNow).execute(bb))).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldRejectSignerWhenRootIsOutsideAcervo() {
        FonteDeConfianca otherAcervo = FonteDeTeste.com(PkiIcpSimulada.criar().raiz());

        assertThat(code(step(good()).execute(SignedArtifactFixture.comAcervo(bb, otherAcervo)))).isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldUseSameAcervoGenerationAcrossValidationSteps() {
        AtomicReference<FonteDeConfianca> vigente = new AtomicReference<>(trust);
        FonteDeConfianca fonte = () -> vigente.get().atual();
        ValidationContext signed = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
        ValidationContext context = new ValidationRequestContextStep(policy, fonte, Clock.systemUTC())
                .execute(signed).context();
        context = new JwsStructureStep().execute(new SignatureBindingStep().execute(context).context()).context();
        vigente.set(FonteDeTeste.com(PkiIcpSimulada.criar().raiz()));

        ValidationContext verified = new SignerCertificateStep(policy, new VerificadoresDss(fonte,
                CertificateVerifierFactory.offline(good(), null))).execute(context).context();
        DssValidationStep dss = new DssValidationStep(new VerificadoresDss(fonte,
                CertificateVerifierFactory.offline(good(), null)), policy);

        assertThat(dss.execute(verified).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectBaselineTSignerChainedToTsaAnchorOutsideAcervo() {
        // signatário e TSA de outra PKI cuja raiz só está no trust store TSA; a allowlist aceita o emissor
        PkiIcpSimulada outra = PkiIcpSimulada.criar();
        try (TsaHttpLocal tsaOutra = outra.iniciarTsaHttp()) {
            SafiraPolicyProperties policyOutra = TestConfigs.policy(outra,
                    TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, outra.raiz()));
            ValidationContext signed = SignedArtifactFixture.validationContext(
                    SignedArtifactFixture.sign(outra, policyOutra, Instant.now().getEpochSecond(), tsaOutra));
            ValidationContext parsed = new JwsStructureStep().execute(new SignatureBindingStep().execute(signed).context()).context();
            DssValidationStep step = new DssValidationStep(new VerificadoresDss(trust,
                    CertificateVerifierFactory.offline(EvidenceRevocationSources.ocspFromEvidence(List.of(
                            outra.ocspBom(outra.signatario()), outra.ocspBom(outra.ac()),
                            outra.ocspBom(tsaOutra.certificado()))), null)), policyOutra);

            StepResult<ValidationContext> result = step.execute(SignedArtifactFixture.comAcervo(parsed, trust));

            assertThat(code(result)).isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
        }
    }

    @Test
    void shouldFailClosedWhenAcervoIsUnavailable() {
        assertThat(code(step(good()).execute(bbSemAcervo))).isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldRejectTimestampWhoseTsaIsOutsideTsaTrustStore() {
        SafiraPolicyProperties otherAnchor = TestConfigs.policy(pki,
                TestConfigs.tsaPolicies(tempDir, PkiIcpSimulada.POLITICA_TSA, 1, PkiIcpSimulada.criar().raiz()));
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(trust,
                CertificateVerifierFactory.offline(good(), null)), otherAnchor);

        assertThat(code(step.execute(bt))).isEqualTo(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldRejectTamperedSignatureValue() {
        String jws = bb.getAttribute(ValidationKeys.JWS_JSON, String.class).orElseThrow();
        String text = bb.getAttribute(ValidationKeys.SIGNATURE_TEXT, String.class).orElseThrow();
        String flipped = (text.charAt(10) == 'A' ? "B" : "A");
        String tampered = jws.replace(text, text.substring(0, 10) + flipped + text.substring(11));

        assertThat(code(step(good())
                .execute(bb.toBuilder().attribute(ValidationKeys.JWS_JSON, tampered).build())))
                .isEqualTo(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED);
    }

    @Test
    void shouldValidateTimestampTokenForBaselineT() {
        assertThat(new TimestampValidationStep(policy).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldSkipTimestampValidationForBaselineB() {
        assertThat(new TimestampValidationStep(policy).execute(bb).isSuccess()).isTrue();
    }

    @Test
    void shouldReturnSuccessOutcomeForNaturalPersonSignature() {
        ValidationContext aprovado = step(good()).execute(bb).context();

        OperationOutcome outcome = new ValidationOutcomeStep().execute(aprovado).context().getOperationOutcome();

        var issue = outcome.issue().getFirst();
        assertThat(issue.severity()).isEqualTo("information");
        assertThat(issue.code()).isEqualTo("informational");
        assertThat(issue.details().coding().getFirst().code()).isEqualTo("VALIDATION.SUCCESS");
        assertThat(issue.details().text()).isEqualTo("Assinatura digital validada com sucesso");
        assertThat(issue.diagnostics()).contains("assinatura PF").contains("JAdES-B-B").contains("RS256");
    }

    @Test
    void shouldCreditRevocationToDssInSuccessDiagnostics() {
        ValidationContext aprovado = step(good()).execute(bb).context();

        String diagnostics = new ValidationOutcomeStep().execute(aprovado).context().getOperationOutcome()
                .issue().getFirst().diagnostics();

        assertThat(diagnostics).contains("revogação decidida pelo EU DSS").doesNotContain("icpbrasil-truststore");
    }

    @Test
    void shouldMarkDssApprovalWhenDssAccepts() {
        ValidationContext aprovado = step(good()).execute(bb).context();

        assertThat(aprovado.getAttribute(ValidationKeys.DSS_APROVADO, Boolean.class)).contains(true);
    }

    @Test
    void shouldFailIndeterminateWhenDssValidationDidNotRun() {
        StepResult<ValidationContext> result = new ValidationOutcomeStep().execute(bb);

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.VALIDATION_INDETERMINATE);
        assertThat(result.context().getOperationOutcome()).isNull();
    }
}
