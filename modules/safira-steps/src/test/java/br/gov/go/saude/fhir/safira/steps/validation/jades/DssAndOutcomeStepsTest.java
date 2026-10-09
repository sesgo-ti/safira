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
import br.gov.go.saude.fhir.safira.jades.fixture.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.trust.icpbrasil.FonteDeConfiancaIcpBrasil;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
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
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/** Steps {@code dss-validation}, {@code timestamp-validation} e {@code validation-outcome}. */
class DssAndOutcomeStepsTest {

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static SafiraPolicyProperties policy;
    private static TrustMaterialSource trust;
    private static ValidationContext bb;
    private static ValidationContext bbSemAcervo;
    private static ValidationContext bt;
    private static Instant btTimestampTime;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
        trust = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert)));
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
        return new SignerCertificateStep(policy, new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
                CertificateVerifierFactory.offline(null, null))).execute(SignedArtifactFixture.comAcervo(parsed, trust)).context();
    }

    /** DSS offline: respostas OCSP prontas (sem rede) sobre o acervo informado. */
    private static DssValidationStep step(RevocationSource<OCSP> ocsp) {
        return new DssValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
                CertificateVerifierFactory.offline(ocsp, null)), policy);
    }

    /** OCSP GOOD, assinado pela CA de teste, para o titular e para a TSA. */
    private static RevocationSource<OCSP> good() {
        return EvidenceRevocationSources.ocspFromEvidence(
                List.of(pki.ocspGoodFor(pki.leafCert), pki.ocspGoodFor(tsa.tsaCert())));
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
                "2.16.76.1.2.201.1", CertificateType.SE_S, pki.issuerSha256())), policy.tsaPolicies(), policy.temporalPolicy());
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
                CertificateVerifierFactory.offline(good(), null)), seloApenas);

        assertThat(code(step.execute(bb))).isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldFailClosedWhenAllowlistIsEmpty() {
        SafiraPolicyProperties semAllowlist = new SafiraPolicyProperties(List.of(), policy.tsaPolicies(), policy.temporalPolicy());
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
                CertificateVerifierFactory.offline(good(), null)), semAllowlist);

        assertThat(code(step.execute(bb))).isEqualTo(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectSignerWithUnknownCriticalExtensionAsChainValidationFailed() {
        TestPki critical = TestPki.create(TestPki.LeafProfile.a3().withUnknownCriticalExtension());
        SafiraPolicyProperties criticalPolicy = TestConfigs.policy(critical,
                TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, critical.caCert));
        TrustMaterialSource criticalTrust = () -> Optional.of(TrustMaterial.of(List.of(critical.caCert)));
        ValidationContext signed = SignedArtifactFixture.validationContext(SignedArtifactFixture.signSemVerificarCadeia(critical, criticalPolicy));
        ValidationContext parsed = new JwsStructureStep().execute(new SignatureBindingStep().execute(signed).context()).context();
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(criticalTrust),
                CertificateVerifierFactory.offline(EvidenceRevocationSources.ocspFromEvidence(
                        List.of(critical.ocspGoodFor(critical.leafCert))), null)), criticalPolicy);

        assertThat(code(step.execute(SignedArtifactFixture.comAcervo(parsed, criticalTrust))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldMapMissingRevocationToRevocationCodeWhenNoSourceAnswers() {
        assertThat(code(step(null).execute(bb))).isEqualTo(SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN);
    }

    @Test
    void shouldRejectRevokedSignerForBaselineB() {
        RevocationSource<OCSP> revoked = EvidenceRevocationSources.ocspFromEvidence(List.of(pki.ocspRevokedFor(pki.leafCert)));

        assertThat(code(step(revoked).execute(bb))).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldAcceptBaselineTWhenSignerIsRevokedAfterTimestamp() {
        // granularidade de segundos do OCSP: revogação claramente posterior ao genTime do carimbo
        Date afterTimestamp = Date.from(btTimestampTime.plusSeconds(2));
        RevocationSource<OCSP> revokedLater = EvidenceRevocationSources.ocspFromEvidence(List.of(
                pki.ocspRevokedFor(pki.leafCert, afterTimestamp), pki.ocspGoodFor(tsa.tsaCert())));

        assertThat(step(revokedLater).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectBaselineBWhenSignerIsRevokedNow() {
        RevocationSource<OCSP> revokedNow = EvidenceRevocationSources.ocspFromEvidence(List.of(
                pki.ocspRevokedFor(pki.leafCert, new Date())));

        assertThat(code(step(revokedNow).execute(bb))).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldRejectSignerWhenRootIsOutsideAcervo() {
        TrustMaterialSource otherAcervo = () -> Optional.of(TrustMaterial.of(List.of(TestPki.create().caCert)));

        assertThat(code(step(good()).execute(SignedArtifactFixture.comAcervo(bb, otherAcervo)))).isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldUseSameAcervoGenerationAcrossValidationSteps() {
        AtomicReference<TrustMaterialSource> vigente = new AtomicReference<>(trust);
        FonteDeConfiancaIcpBrasil fonte = new FonteDeConfiancaIcpBrasil(() -> vigente.get().current());
        ValidationContext signed = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
        ValidationContext context = new ValidationRequestContextStep(policy, fonte, Clock.systemUTC())
                .execute(signed).context();
        context = new JwsStructureStep().execute(new SignatureBindingStep().execute(context).context()).context();
        vigente.set(() -> Optional.of(TrustMaterial.of(List.of(TestPki.create().caCert))));

        ValidationContext verified = new SignerCertificateStep(policy, new VerificadoresDss(fonte,
                CertificateVerifierFactory.offline(good(), null))).execute(context).context();
        DssValidationStep dss = new DssValidationStep(new VerificadoresDss(fonte,
                CertificateVerifierFactory.offline(good(), null)), policy);

        assertThat(dss.execute(verified).isSuccess()).isTrue();
    }

    @Test
    void shouldFailClosedWhenAcervoIsUnavailable() {
        assertThat(code(step(good()).execute(bbSemAcervo))).isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldRejectTimestampWhoseTsaIsOutsideTsaTrustStore() {
        SafiraPolicyProperties otherAnchor = TestConfigs.policy(pki,
                TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, TestPki.create().caCert));
        DssValidationStep step = new DssValidationStep(new VerificadoresDss(new FonteDeConfiancaIcpBrasil(trust),
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
        OperationOutcome outcome = new ValidationOutcomeStep().execute(bb).context().getOperationOutcome();

        var issue = outcome.issue().getFirst();
        assertThat(issue.severity()).isEqualTo("information");
        assertThat(issue.code()).isEqualTo("informational");
        assertThat(issue.details().coding().getFirst().code()).isEqualTo("VALIDATION.SUCCESS");
        assertThat(issue.details().text()).isEqualTo("Assinatura digital validada com sucesso");
        assertThat(issue.diagnostics()).contains("assinatura PF").contains("JAdES-B-B").contains("RS256");
    }
}
