/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.ConfigViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TemporalPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TrustStoreRef;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicies;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class SafiraPolicyPropertiesTest {

    private static final String ISSUER = "a".repeat(64);
    private static final AcceptedCertificatePolicy A3 =
            new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3, ISSUER);

    @TempDir
    static Path tempDir;
    private static String tsaStoreReference;

    @BeforeAll
    static void createTsaStore() throws Exception {
        tsaStoreReference = "file:" + TsaTrustStoresTest.writePem(tempDir, TestPki.create().caCert);
    }

    private static SafiraPolicyProperties properties(List<AcceptedCertificatePolicy> allowlist, TsaPolicies tsa) {
        return new SafiraPolicyProperties(allowlist, tsa, new TemporalPolicy(1751328000L));
    }

    private static TsaPolicies tsa(TsaPolicy... policies) {
        return new TsaPolicies("1.0.0", List.of(policies));
    }

    private static List<SignatureExceptionCode> codes(List<ConfigViolation> violations) {
        return violations.stream().map(ConfigViolation::code).toList();
    }

    @Test
    void shouldAcceptValidConfigurationWithoutTsa() {
        assertThat(properties(List.of(A3), null).violations(false)).isEmpty();
    }

    @Test
    void shouldRejectEmptyAllowlist() {
        assertThat(codes(properties(List.of(), null).violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectAllowlistOidWithSixArcs() {
        var entry = new AcceptedCertificatePolicy("2.16.76.1.2.3", CertificateType.A3, ISSUER);

        assertThat(codes(properties(List.of(entry), null).violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectOidOutsideTypeBranch() {
        var entry = new AcceptedCertificatePolicy("2.16.76.1.2.4.1", CertificateType.A3, ISSUER);

        assertThat(codes(properties(List.of(entry), null).violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectUppercaseIssuerSha256() {
        var entry = new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3, "A".repeat(64));

        assertThat(codes(properties(List.of(entry), null).violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectDuplicateAllowlistEntries() {
        assertThat(codes(properties(List.of(A3, A3), null).violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRequireTsaPoliciesOnlyWhenTsaRequested() {
        SafiraPolicyProperties withoutTsa = properties(List.of(A3), null);

        assertThat(withoutTsa.violations(false)).isEmpty();
        assertThat(codes(withoutTsa.violations(true)))
                .containsExactly(SignatureExceptionCode.CONFIG_MISSING_PARAMETER);
    }

    @Test
    void shouldAcceptValidTsaPolicy() {
        var tsa = tsa(new TsaPolicy("1.2.3.4.5", 1L, new TrustStoreRef(tsaStoreReference)));

        assertThat(properties(List.of(A3), tsa).violations(true)).isEmpty();
    }

    @Test
    void shouldRejectDuplicateTsaOid() {
        var policy = new TsaPolicy("1.2.3.4.5", 1L, new TrustStoreRef(tsaStoreReference));

        assertThat(codes(properties(List.of(A3), tsa(policy, policy)).violations(true)))
                .containsExactly(SignatureExceptionCode.CONFIG_TSA_OID_INVALID);
    }

    @Test
    void shouldRejectMalformedTsaOid() {
        var policy = new TsaPolicy("urn:oid:1.2.3", 1L, new TrustStoreRef(tsaStoreReference));

        assertThat(codes(properties(List.of(A3), tsa(policy)).violations(true)))
                .containsExactly(SignatureExceptionCode.CONFIG_TSA_OID_INVALID);
    }

    @Test
    void shouldRejectNonPositiveAccuracy() {
        var policy = new TsaPolicy("1.2.3.4.5", 0L, new TrustStoreRef(tsaStoreReference));

        assertThat(codes(properties(List.of(A3), tsa(policy)).violations(true)))
                .containsExactly(SignatureExceptionCode.CONFIG_INVALID_PARAMETER);
    }

    @Test
    void shouldRejectUnreadableTsaTrustStore() {
        var policy = new TsaPolicy("1.2.3.4.5", 1L, new TrustStoreRef("file:/nao/existe.pem"));

        assertThat(codes(properties(List.of(A3), tsa(policy)).violations(true)))
                .containsExactly(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    @Test
    void shouldRejectMinCertIssueDateOutOfRange() {
        var props = new SafiraPolicyProperties(List.of(A3), null, new TemporalPolicy(1000L));

        assertThat(codes(props.violations(false)))
                .containsExactly(SignatureExceptionCode.CONFIG_CERT_MIN_DATE_OUT_OF_RANGE);
    }

    @Test
    void shouldDefaultMinCertIssueDateWhenAbsent() {
        var props = new SafiraPolicyProperties(List.of(A3), null, null);

        assertThat(props.minCertIssueDate()).isEqualTo(1751328000L);
    }
}
