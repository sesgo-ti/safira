/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationEvidence;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationLookup;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Steps {@code dss-validation}, {@code timestamp-validation} e {@code validation-outcome}. */
class DssAndOutcomeStepsTest {

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static TestPki.FakeTsa tsa;
    private static SafiraPolicyProperties policy;
    private static TrustMaterialSource trust;
    private static ValidationContext bb;
    private static ValidationContext bt;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        tsa = pki.startFakeTsa();
        policy = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
        trust = () -> Optional.of(TrustMaterial.of(List.of(pki.caCert)));
        bb = structured(SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy)));
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
        return new SignerCertificateStep(policy, trust).execute(parsed).context();
    }

    /** Revogação da lib: OCSP GOOD assinado pela CA de teste para qualquer certificado. */
    private static RevocationService goodRevocation() {
        RevocationService service = mock(RevocationService.class);
        when(service.lookup(any(), any())).thenAnswer(invocation -> {
            byte[] der = pki.ocspGoodFor(invocation.getArgument(0, X509Certificate.class));
            return new RevocationLookup(new RevocationStatus.Good("OCSP", der), new RevocationEvidence.OcspResponse(der));
        });
        return service;
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    @Test
    void shouldAcceptBaselineBThroughDss() {
        assertThat(new DssValidationStep(goodRevocation(), trust, policy).execute(bb).isSuccess()).isTrue();
    }

    @Test
    void shouldAcceptBaselineTThroughDss() {
        assertThat(new DssValidationStep(goodRevocation(), trust, policy).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldMapInconclusiveRevocationToRevocationCode() {
        RevocationService unavailable = mock(RevocationService.class);
        when(unavailable.lookup(any(), any()))
                .thenReturn(RevocationLookup.inconclusive(new RevocationStatus.NoConnectivity()));

        assertThat(code(new DssValidationStep(unavailable, trust, policy).execute(bb)))
                .isEqualTo(SignatureExceptionCode.REVOCATION_NO_CONNECTIVITY);
    }

    @Test
    void shouldRejectRevokedSignerForBaselineB() {
        RevocationService revoked = mock(RevocationService.class);
        when(revoked.lookup(any(), any())).thenAnswer(invocation -> {
            byte[] der = pki.ocspGoodFor(invocation.getArgument(0, X509Certificate.class));
            return new RevocationLookup(new RevocationStatus.Revoked("OCSP"), new RevocationEvidence.OcspResponse(der));
        });

        assertThat(code(new DssValidationStep(revoked, trust, policy).execute(bb))).isEqualTo(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldRejectTamperedSignatureValue() {
        String jws = bb.getAttribute(ValidationKeys.JWS_JSON, String.class).orElseThrow();
        String text = bb.getAttribute(ValidationKeys.SIGNATURE_TEXT, String.class).orElseThrow();
        String flipped = (text.charAt(10) == 'A' ? "B" : "A");
        String tampered = jws.replace(text, text.substring(0, 10) + flipped + text.substring(11));

        assertThat(code(new DssValidationStep(goodRevocation(), trust, policy)
                .execute(bb.toBuilder().attribute(ValidationKeys.JWS_JSON, tampered).build())))
                .isEqualTo(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED);
    }

    @Test
    void shouldValidateTimestampTokenForBaselineT() {
        assertThat(new TimestampValidationStep(policy).execute(bt).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectTimestampWhoseTsaIsOutsideTsaTrustStore() {
        SafiraPolicyProperties otherAnchor = TestConfigs.policy(pki,
                TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, TestPki.create().caCert));

        assertThat(code(new TimestampValidationStep(otherAnchor).execute(bt)))
                .isEqualTo(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED);
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
