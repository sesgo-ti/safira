/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.PerfilSignatario;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class IcpBrasilCertificateProfileTest {

    private static final long MIN_DATE = 1751328000L;

    private static PkiIcpSimulada a3;

    @BeforeAll
    static void createPki() {
        a3 = PkiIcpSimulada.criar();
    }

    private static List<AcceptedCertificatePolicy> allowlist(PkiIcpSimulada pki, String oid, CertificateType type) {
        return List.of(new AcceptedCertificatePolicy(oid, type, pki.emissorSha256()));
    }

    private static ProfileResult evaluate(PkiIcpSimulada pki, List<AcceptedCertificatePolicy> allowlist) {
        return IcpBrasilCertificateProfile.evaluate(pki.signatario(), pki.ac(), allowlist, MIN_DATE);
    }

    private static SignatureExceptionCode rejection(ProfileResult result) {
        assertThat(result).isInstanceOf(ProfileResult.Rejected.class);
        return ((ProfileResult.Rejected) result).code();
    }

    @Test
    void shouldAcceptA3LeafMatchingAllowlist() {
        ProfileResult result = evaluate(a3, allowlist(a3, "2.16.76.1.2.3.1", CertificateType.A3));

        assertThat(result).isEqualTo(new ProfileResult.Eligible(
                new SignerIdentity(CertificateType.A3, SignerIdentity.CPF_SYSTEM, PkiIcpSimulada.CPF),
                "2.16.76.1.2.3.1"));
    }

    @Test
    void shouldExtractCnpjForSeS() {
        PkiIcpSimulada seS = PkiIcpSimulada.criar(PerfilSignatario.seS());

        ProfileResult result = evaluate(seS, allowlist(seS, "2.16.76.1.2.201.1", CertificateType.SE_S));

        assertThat(result).isEqualTo(new ProfileResult.Eligible(
                new SignerIdentity(CertificateType.SE_S, SignerIdentity.CNPJ_SYSTEM, PkiIcpSimulada.CNPJ),
                "2.16.76.1.2.201.1"));
    }

    @Test
    void shouldRejectPolicyAbsentFromAllowlist() {
        PkiIcpSimulada a1 = PkiIcpSimulada.criar(PerfilSignatario.a3().comPolitica("2.16.76.1.2.1.1"));

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
        PkiIcpSimulada any = PkiIcpSimulada.criar(PerfilSignatario.a3().comPolitica("2.5.29.32.0"));

        assertThat(rejection(evaluate(any, allowlist(any, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldRejectEcKey() {
        PkiIcpSimulada ec = PkiIcpSimulada.criar(PerfilSignatario.a3().comChave("EC", 0));

        assertThat(rejection(evaluate(ec, allowlist(ec, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM);
    }

    @Test
    void shouldRejectRsa3072ForA3() {
        PkiIcpSimulada big = PkiIcpSimulada.criar(PerfilSignatario.a3().comChave("RSA", 3072));

        assertThat(rejection(evaluate(big, allowlist(big, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_WEAK_KEY);
    }

    @Test
    void shouldRejectLeafWithoutDigitalSignature() {
        PkiIcpSimulada noDs = PkiIcpSimulada.criar(PerfilSignatario.a3().comKeyUsage(KeyUsage.nonRepudiation));

        assertThat(rejection(evaluate(noDs, allowlist(noDs, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldNotRequireNonRepudiation() {
        PkiIcpSimulada dsOnly = PkiIcpSimulada.criar(PerfilSignatario.a3().comKeyUsage(KeyUsage.digitalSignature));

        assertThat(evaluate(dsOnly, allowlist(dsOnly, "2.16.76.1.2.3.1", CertificateType.A3)))
                .isInstanceOf(ProfileResult.Eligible.class);
    }

    @Test
    void shouldRejectCertificateIssuedBeforeMinimumDate() {
        ProfileResult result = IcpBrasilCertificateProfile.evaluate(a3.signatario(), a3.ac(),
                allowlist(a3, "2.16.76.1.2.3.1", CertificateType.A3), a3.inicioValidade() + 1);

        assertThat(rejection(result)).isEqualTo(SignatureExceptionCode.CERT_ISSUE_DATE_TOO_OLD);
    }

    @Test
    void shouldRejectDivergentCpfBetweenSerialNumberAndSan() {
        PkiIcpSimulada divergent = PkiIcpSimulada.criar(PerfilSignatario.a3().comDn("CN=Fulano,SERIALNUMBER=11144477735"));

        assertThat(rejection(evaluate(divergent, allowlist(divergent, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldRejectInvalidCpfCheckDigits() {
        PkiIcpSimulada invalid = PkiIcpSimulada.criar(PerfilSignatario.a3()
                .comDn("CN=Fulano")
                .comSan("2.16.76.1.3.1", "01011990" + "12345678901" + "000000000000000000"));

        assertThat(rejection(evaluate(invalid, allowlist(invalid, "2.16.76.1.2.3.1", CertificateType.A3))))
                .isEqualTo(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION);
    }

    @Test
    void shouldAcceptIdentityOnlyInSan() {
        PkiIcpSimulada sanOnly = PkiIcpSimulada.criar(PerfilSignatario.a3().comDn("CN=Fulano de Tal"));

        assertThat(evaluate(sanOnly, allowlist(sanOnly, "2.16.76.1.2.3.1", CertificateType.A3)))
                .isInstanceOf(ProfileResult.Eligible.class);
    }

    @Test
    void shouldRejectCnpjOnNaturalPersonCertificate() {
        PkiIcpSimulada wrong = PkiIcpSimulada.criar(PerfilSignatario.a3()
                .comDn("CN=Fulano")
                .comSan("2.16.76.1.3.3", PkiIcpSimulada.CNPJ));

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
