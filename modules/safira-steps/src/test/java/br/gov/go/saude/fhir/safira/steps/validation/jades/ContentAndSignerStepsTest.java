/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.FonteDeTeste;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;


import static org.assertj.core.api.Assertions.assertThat;

/** Steps {@code content-integrity} e {@code signer-certificate}. */
class ContentAndSignerStepsTest {

    private static PkiIcpSimulada pki;
    private static SafiraPolicyProperties policy;
    private static FonteDeConfianca trust;
    private static ValidationContext structured;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        policy = TestConfigs.policy(pki);
        trust = FonteDeTeste.com(pki.raiz(), pki.ac());
        ValidationContext context = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
        context = new SignatureBindingStep().execute(context).context();
        structured = new JwsStructureStep().execute(context).context();
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    private static StepResult<ValidationContext> signer(SafiraPolicyProperties properties, FonteDeConfianca source,
                                                        ValidationContext context) {
        return new SignerCertificateStep(properties, new VerificadoresDss(source,
                CertificateVerifierFactory.offline(null, null)))
                .execute(SignedArtifactFixture.comAcervo(context, source));
    }

    @Test
    void shouldConfirmContentIntegrity() {
        assertThat(new ContentIntegrityStep().execute(structured).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectTamperedResource() {
        ValidationContext tampered = structured.toBuilder()
                .bundleJson(LosslessJson.parseObject(SignedArtifactFixture.BUNDLE.replace("13.50", "13.5")))
                .build();

        assertThat(code(new ContentIntegrityStep().execute(tampered)))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED);
    }

    @Test
    void shouldRejectReorderedTargets() {
        String reordered = LosslessJson.write(structured.getProvenanceJson())
                .replace(SignedArtifactFixture.U2, "TMP").replace(SignedArtifactFixture.U1, SignedArtifactFixture.U2)
                .replace("TMP", SignedArtifactFixture.U1);

        assertThat(code(new ContentIntegrityStep().execute(structured.toBuilder()
                .provenanceJson(LosslessJson.parseObject(reordered)).build())))
                .isEqualTo(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED);
    }

    @Test
    void shouldAcceptSignerCertificate() {
        StepResult<ValidationContext> result = signer(policy, trust, structured);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getAttribute(ValidationKeys.SIGNER_IDENTITY, Object.class)).isPresent();
    }

    @Test
    void shouldRejectWhenDiffersFromIat() {
        ValidationContext changed = structured.toBuilder()
                .signatureJson(structured.getSignatureJson().with("when", new JsonString("2026-01-01T00:00:00Z")))
                .build();

        assertThat(code(signer(policy, trust, changed)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldRejectIatAfterReferenceTimestamp() {
        ValidationContext earlier = structured.toBuilder()
                .referenceTimestamp(structured.getAttribute(ValidationKeys.IAT, Long.class).orElseThrow() - 1)
                .build();

        assertThat(code(signer(policy, trust, earlier)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldLeaveRootTrustToDssWhenProfileAccepts() {
        FonteDeConfianca other = FonteDeTeste.com(PkiIcpSimulada.criar().raiz());

        assertThat(signer(policy, other, structured).isSuccess()).isTrue();
    }

    @Test
    void shouldReportNotIcpBrasilWhenRootIsOutsideAcervoAndIssuerNotInAllowlist() {
        PkiIcpSimulada other = PkiIcpSimulada.criar();
        FonteDeConfianca otherAcervo = FonteDeTeste.com(other.raiz(), other.ac());

        assertThat(code(signer(TestConfigs.policy(other), otherAcervo, structured)))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldReportPolicyComplianceWhenLeafPolicyNotInAllowlist() {
        PkiIcpSimulada other = PkiIcpSimulada.criar();

        assertThat(code(signer(TestConfigs.policy(other), trust, structured)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectSignatureWhoDifferentFromCertificate() {
        String who = LosslessJson.write(structured.getSignatureJson()).replace(PkiIcpSimulada.CPF, "11144477735");

        assertThat(code(signer(policy, trust, structured.toBuilder()
                .signatureJson(LosslessJson.parseObject(who)).build())))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }
}
