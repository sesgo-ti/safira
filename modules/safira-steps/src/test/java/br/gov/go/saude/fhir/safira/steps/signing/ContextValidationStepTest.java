/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.support.TestConfigs;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ContextValidationStepTest {

    private static final long NOW = 1790000000L;
    private static final Clock CLOCK = Clock.fixed(Instant.ofEpochSecond(NOW), ZoneOffset.UTC);

    @TempDir
    static Path tempDir;
    private static TestPki pki;
    private static SafiraPolicyProperties policy;
    private static SafiraPolicyProperties policyWithTsa;

    @BeforeAll
    static void setUp() {
        pki = TestPki.create();
        policy = TestConfigs.policy(pki);
        policyWithTsa = TestConfigs.policy(pki, TestConfigs.tsaPolicies(tempDir, TestPki.TSA_POLICY_OID, 1, pki.caCert));
    }

    private static SigningContext.SigningContextBuilder valid() {
        return SigningContext.builder()
                .policyIdentifierUri(Policy020.POLICY_URI)
                .referenceTimestamp(NOW)
                .strategy(TimestampStrategy.IAT)
                .cryptoMaterial(new CryptoMaterial.PemMaterial("pem", null))
                .rawCertificateChain(List.of("x"))
                .operationalConfig(TestConfigs.operational());
    }

    private static StepResult<SigningContext> run(SigningContext.SigningContextBuilder builder) {
        return new ContextValidationStep(policy, CLOCK).execute(builder.build());
    }

    private static SignatureExceptionCode code(StepResult<SigningContext> result) {
        assertThat(result).isInstanceOf(StepResult.Failure.class);
        return ((StepResult.Failure<SigningContext>) result).code();
    }

    @Test
    void shouldAcceptValidContext() {
        assertThat(run(valid()).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectMissingPolicy() {
        assertThat(code(run(valid().policyIdentifierUri(" ")))).isEqualTo(SignatureExceptionCode.POLICY_MISSING);
    }

    @Test
    void shouldRejectLegacyPipeSeparatedPolicyUri() {
        String legacy = "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|2.0.0";

        assertThat(code(run(valid().policyIdentifierUri(legacy)))).isEqualTo(SignatureExceptionCode.POLICY_URI_INVALID);
    }

    @Test
    void shouldRejectHttpPolicyUri() {
        String http = "http://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.2.0";

        assertThat(code(run(valid().policyIdentifierUri(http)))).isEqualTo(SignatureExceptionCode.POLICY_URI_INVALID);
    }

    @Test
    void shouldRejectOtherPolicyVersion() {
        String other = "https://fhir.saude.go.gov.br/r4/seguranca/assinatura/politica/0.3.0";

        assertThat(code(run(valid().policyIdentifierUri(other))))
                .isEqualTo(SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED);
    }

    @Test
    void shouldRejectTimestampOutsidePolicyRange() {
        assertThat(code(run(valid().referenceTimestamp(1700000000L))))
                .isEqualTo(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP);
    }

    @Test
    void shouldRejectTimestampBeyondClockTolerance() {
        assertThat(code(run(valid().referenceTimestamp(NOW - 301))))
                .isEqualTo(SignatureExceptionCode.FORMAT_INVALID_TIMESTAMP);
    }

    @Test
    void shouldAcceptTimestampWithinClockTolerance() {
        assertThat(run(valid().referenceTimestamp(NOW + 300)).isSuccess()).isTrue();
    }

    @Test
    void shouldRejectMissingTimestamp() {
        assertThat(code(run(valid().referenceTimestamp(null))))
                .isEqualTo(SignatureExceptionCode.CONFIG_INVALID_TIMESTAMP_FORMAT);
    }

    @Test
    void shouldRejectMissingStrategy() {
        assertThat(code(run(valid().strategy(null)))).isEqualTo(SignatureExceptionCode.CONFIG_INVALID_STRATEGY);
    }

    @Test
    void shouldRequireTsaUrlForTsaStrategy() {
        StepResult<SigningContext> result = new ContextValidationStep(policyWithTsa, CLOCK)
                .execute(valid().strategy(TimestampStrategy.TSA).build());

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CONFIG_MISSING_PARAMETER);
    }

    @Test
    void shouldRejectHttpTsaUrl() {
        StepResult<SigningContext> result = new ContextValidationStep(policyWithTsa, CLOCK).execute(valid()
                .strategy(TimestampStrategy.TSA)
                .operationalConfig(TestConfigs.operational("http://tsa.example.com"))
                .build());

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CONFIG_TSA_URL_INVALID);
    }

    @Test
    void shouldRequireTsaPoliciesForTsaStrategy() {
        StepResult<SigningContext> result = run(valid()
                .strategy(TimestampStrategy.TSA)
                .operationalConfig(TestConfigs.operational("https://tsa.example.com")));

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CONFIG_MISSING_PARAMETER);
    }

    @Test
    void shouldAcceptCompleteTsaConfiguration() {
        StepResult<SigningContext> result = new ContextValidationStep(policyWithTsa, CLOCK).execute(valid()
                .strategy(TimestampStrategy.TSA)
                .operationalConfig(TestConfigs.operational("https://tsa.example.com"))
                .build());

        assertThat(result.isSuccess()).isTrue();
    }

    @Test
    void shouldRejectEmptyAllowlist() {
        SafiraPolicyProperties empty = new SafiraPolicyProperties(List.of(), null, null);

        StepResult<SigningContext> result = new ContextValidationStep(empty, CLOCK).execute(valid().build());

        assertThat(code(result)).isEqualTo(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectPkcs12WithoutPassword() {
        assertThat(code(run(valid().cryptoMaterial(new CryptoMaterial.Pkcs12Material("AA==", "", "a")))))
                .isEqualTo(SignatureExceptionCode.CONFIG_MISSING_PARAMETER);
    }
}
