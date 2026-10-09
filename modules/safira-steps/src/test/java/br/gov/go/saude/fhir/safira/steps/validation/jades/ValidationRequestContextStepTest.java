/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.FonteDeTeste;
import br.gov.go.saude.fhir.safira.steps.support.SignedArtifactFixture;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class ValidationRequestContextStepTest {

    private static PkiIcpSimulada pki;
    private static SafiraPolicyProperties policy;
    private static ValidationContext valid;

    @BeforeAll
    static void setUp() {
        pki = PkiIcpSimulada.criar();
        policy = TestConfigs.policy(pki);
        valid = SignedArtifactFixture.validationContext(SignedArtifactFixture.sign(pki, policy));
    }

    private static StepResult<ValidationContext> run(ValidationContext context, FonteDeConfianca trust) {
        return new ValidationRequestContextStep(policy, trust, Clock.systemUTC()).execute(context);
    }

    private static FonteDeConfianca loaded() {
        return FonteDeTeste.com(pki.raiz(), pki.ac());
    }

    private static SignatureExceptionCode code(StepResult<ValidationContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<ValidationContext>) result).code();
    }

    @Test
    void shouldAcceptCompleteRequest() {
        assertThat(run(valid, loaded()).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectMissingSignature() {
        assertThat(code(run(valid.toBuilder().signatureJson(null).build(), loaded())))
                .isEqualTo(SignatureExceptionCode.FORMAT_SIGNATURE_MISSING);
    }

    @Test
    void shouldRejectMissingBundle() {
        assertThat(code(run(valid.toBuilder().bundleJson(null).build(), loaded())))
                .isEqualTo(SignatureExceptionCode.FORMAT_BUNDLE_MALFORMED);
    }

    @Test
    void shouldRejectMissingProvenance() {
        assertThat(code(run(valid.toBuilder().provenanceJson(null).build(), loaded())))
                .isEqualTo(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID);
    }

    @Test
    void shouldRejectOtherPolicyVersion() {
        ValidationContext context = valid.toBuilder()
                .policyIdentifierUri("https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.1.0").build();

        assertThat(code(run(context, loaded()))).isEqualTo(SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED);
    }

    @Test
    void shouldRejectReferenceTimestampFarFromServerClock() {
        ValidationContext context = valid.toBuilder().referenceTimestamp(valid.getReferenceTimestamp() - 3600).build();

        assertThat(code(run(context, loaded()))).isEqualTo(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP);
    }

    @Test
    void shouldRejectWhenTrustStoreIsNotLoaded() {
        assertThat(code(run(valid, Optional::empty))).isEqualTo(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldStoreAcervoSnapshotInContext() {
        StepResult<ValidationContext> result = run(valid, loaded());

        assertThat(result.context().getAttribute(ValidationKeys.ACERVO, AcervoDeConfianca.class)).isPresent();
    }

    @Test
    void shouldQueryFonteOnlyOncePerExecution() {
        AtomicInteger calls = new AtomicInteger();
        FonteDeConfianca fonte = () -> {
            calls.incrementAndGet();
            return loaded().atual();
        };

        new ValidationRequestContextStep(policy, fonte, Clock.systemUTC()).execute(valid);

        assertThat(calls).hasValue(1);
    }
}
