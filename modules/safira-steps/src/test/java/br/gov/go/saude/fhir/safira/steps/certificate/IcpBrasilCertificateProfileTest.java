/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki.LeafProfile;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IcpBrasilCertificateProfileTest {

    private static final long MIN_DATE = 1751328000L;

    private static TestPki a3;

    @BeforeAll
    static void createPki() {
        a3 = TestPki.create();
    }

    private static List<AcceptedCertificatePolicy> allowlist(TestPki pki, String oid, CertificateType type) {
        return List.of(new AcceptedCertificatePolicy(oid, type, pki.issuerSha256()));
    }

    private static ProfileResult evaluate(TestPki pki, List<AcceptedCertificatePolicy> allowlist) {
        return IcpBrasilCertificateProfile.evaluate(pki.leafCert, pki.caCert, allowlist, MIN_DATE);
    }

    private static SignatureExceptionCode rejection(ProfileResult result) {
        assertThat(result).isInstanceOf(ProfileResult.Rejected.class);
        return ((ProfileResult.Rejected) result).code();
    }

    @Test
    void shouldAcceptA3LeafMatchingAllowlist() {
        ProfileResult result = evaluate(a3, allowlist(a3, "2.16.76.1.2.3.1", CertificateType.A3));

        assertThat(result).isEqualTo(new ProfileResult.Eligible(
                new SignerIdentity(CertificateType.A3, SignerIdentity.CPF_SYSTEM, TestPki.TEST_CPF),
                "2.16.76.1.2.3.1"));
    }

    @Test
    void shouldExtractCnpjForSeS() {
        TestPki seS = TestPki.create(LeafProfile.seS());

        ProfileResult result = evaluate(seS, allowlist(seS, "2.16.76.1.2.201.1", CertificateType.SE_S));

        assertThat(result).isEqualTo(new ProfileResult.Eligible(
                new SignerIdentity(CertificateType.SE_S, SignerIdentity.CNPJ_SYSTEM, TestPki.TEST_CNPJ),
                "2.16.76.1.2.201.1"));
    }

    @Test
    void shouldRejectPolicyAbsentFromAllowlist() {
        TestPki a1 = TestPki.create(LeafProfile.a3().withPolicyOid("2.16.76.1.2.1.1"));

        assertThat(rejection(evaluate(a1, allowlist(a1, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectAllowlistEntryWithOtherIssuer() {
        var entry = List.of(new AcceptedCertificatePolicy("2.16.76.1.2.3.1", CertificateType.A3, "0".repeat(64)));

        assertThat(rejection(evaluate(a3, entry))).isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectAnyPolicy() {
        TestPki any = TestPki.create(LeafProfile.a3().withPolicyOid("2.5.29.32.0"));

        assertThat(rejection(evaluate(any, allowlist(any, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectEcKey() {
        TestPki ec = TestPki.create(LeafProfile.a3().withKey("EC", 0));

        assertThat(rejection(evaluate(ec, allowlist(ec, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM);
    }

    @Test
    void shouldRejectRsa3072ForA3() {
        TestPki big = TestPki.create(LeafProfile.a3().withKey("RSA", 3072));

        assertThat(rejection(evaluate(big, allowlist(big, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_WEAK_KEY);
    }

    @Test
    void shouldRejectLeafWithoutDigitalSignature() {
        TestPki noDs = TestPki.create(LeafProfile.a3().withKeyUsage(KeyUsage.nonRepudiation));

        assertThat(rejection(evaluate(noDs, allowlist(noDs, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldNotRequireNonRepudiation() {
        TestPki dsOnly = TestPki.create(LeafProfile.a3().withKeyUsage(KeyUsage.digitalSignature));

        assertThat(evaluate(dsOnly, allowlist(dsOnly, "2.16.76.1.2.3.1", CertificateType.A3)))
                .isInstanceOf(ProfileResult.Eligible.class);
    }

    @Test
    void shouldRejectCertificateIssuedBeforeMinimumDate() {
        ProfileResult result = IcpBrasilCertificateProfile.evaluate(a3.leafCert, a3.caCert,
                allowlist(a3, "2.16.76.1.2.3.1", CertificateType.A3), MIN_DATE + 1);

        assertThat(rejection(result)).isEqualTo(SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD);
    }

    @Test
    void shouldRejectDivergentCpfBetweenSerialNumberAndSan() {
        TestPki divergent = TestPki.create(LeafProfile.a3().withSubjectDn("CN=Fulano,SERIALNUMBER=11144477735"));

        assertThat(rejection(evaluate(divergent, allowlist(divergent, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldRejectInvalidCpfCheckDigits() {
        TestPki invalid = TestPki.create(LeafProfile.a3()
                .withSubjectDn("CN=Fulano")
                .withSan("2.16.76.1.3.1", "01011990" + "12345678901" + "000000000000000000"));

        assertThat(rejection(evaluate(invalid, allowlist(invalid, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldAcceptIdentityOnlyInSan() {
        TestPki sanOnly = TestPki.create(LeafProfile.a3().withSubjectDn("CN=Fulano de Tal"));

        assertThat(evaluate(sanOnly, allowlist(sanOnly, "2.16.76.1.2.3.1", CertificateType.A3)))
                .isInstanceOf(ProfileResult.Eligible.class);
    }

    @Test
    void shouldRejectCnpjOnNaturalPersonCertificate() {
        TestPki wrong = TestPki.create(LeafProfile.a3()
                .withSubjectDn("CN=Fulano")
                .withSan("2.16.76.1.3.3", TestPki.TEST_CNPJ));

        assertThat(rejection(evaluate(wrong, allowlist(wrong, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldValidateCpfAndCnpjCheckDigits() {
        assertThat(IcpBrasilCertificateProfile.isValidCpf("52998224725")).isTrue();
        assertThat(IcpBrasilCertificateProfile.isValidCpf("11111111111")).isFalse();
        assertThat(IcpBrasilCertificateProfile.isValidCnpj("11222333000181")).isTrue();
        assertThat(IcpBrasilCertificateProfile.isValidCnpj("11222333000180")).isFalse();
    }
}
