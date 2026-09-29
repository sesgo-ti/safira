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
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.CertPathValidatorException.BasicReason;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Steps {@code content-integrity}, {@code signer-certificate} e {@code current-chain}. */
class ContentAndSignerStepsTest {

    private static TestPki pki;
    private static SafiraPolicyProperties policy;
    private static TrustMaterialSource trust;
    private static ValidationContext structured;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        policy = TestConfigs.policy(pki);
        trust = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert)));
        ValidationContext context = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
        context = new SignatureBindingStep().execute(context).context();
        structured = new JwsStructureStep().execute(context).context();
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
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
        StepResult<ValidationContext> result = new SignerCertificateStep(policy, trust).execute(structured);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.context().getAttribute(ValidationKeys.SIGNER_IDENTITY, Object.class)).isPresent();
    }

    @Test
    void shouldRejectWhenDiffersFromIat() {
        ValidationContext changed = structured.toBuilder()
                .signatureJson(structured.getSignatureJson().with("when", new JsonString("2026-01-01T00:00:00Z")))
                .build();

        assertThat(code(new SignerCertificateStep(policy, trust).execute(changed)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldRejectIatAfterReferenceTimestamp() {
        ValidationContext earlier = structured.toBuilder()
                .referenceTimestamp(structured.getAttribute(ValidationKeys.IAT, Long.class).orElseThrow() - 1)
                .build();

        assertThat(code(new SignerCertificateStep(policy, trust).execute(earlier)))
                .isEqualTo(SignatureExceptionCode.TEMPORAL_IAT_INVALID);
    }

    @Test
    void shouldRejectRootOutsideTrustStore() {
        TrustMaterialSource other = () -> Optional.of(TrustMaterial.of(List.of(TestPki.create().caCert)));

        assertThat(code(new SignerCertificateStep(policy, other).execute(structured)))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldReportPolicyComplianceWhenLeafPolicyNotInAllowlist() {
        TestPki other = TestPki.create();

        assertThat(code(new SignerCertificateStep(TestConfigs.policy(other), trust).execute(structured)))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldRejectSignatureWhoDifferentFromCertificate() {
        String who = LosslessJson.write(structured.getSignatureJson()).replace(TestPki.TEST_CPF, "11144477735");

        assertThat(code(new SignerCertificateStep(policy, trust).execute(structured.toBuilder()
                .signatureJson(LosslessJson.parseObject(who)).build())))
                .isEqualTo(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED);
    }

    @Test
    void shouldValidateCurrentChainForBaselineB() {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Untrusted(BasicReason.EXPIRED, "expirado"));

        assertThat(code(new CurrentChainStep(validator).execute(structured))).isEqualTo(SignatureExceptionCode.CERT_EXPIRED);
    }

    @Test
    void shouldSkipCurrentChainForBaselineT() {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);

        StepResult<ValidationContext> result = new CurrentChainStep(validator)
                .execute(structured.toBuilder().attribute(ValidationKeys.JADES_LEVEL, JadesLevel.B_T).build());

        assertThat(result.isSuccess()).isTrue();
        verify(validator, never()).validate(any(), anyCollection());
    }
}
