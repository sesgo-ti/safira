/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.fhir.safira.steps.certificate.CertificateType;
import br.gov.go.saude.fhir.safira.steps.certificate.IcpBrasilCertificateProfile;
import br.gov.go.saude.fhir.safira.steps.certificate.ProfileResult;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GeradorPkiSimuladaTest {

    @TempDir
    static Path saida;

    static Resultado resultado;

    @BeforeAll
    static void gerar() {
        resultado = GeradorPkiSimulada.gerar(saida, Opcoes.padrao().comSenha("senha-teste"));
    }

    private static X509Certificate certificado(Path pem) throws Exception {
        try (InputStream in = Files.newInputStream(pem)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static X509CRL lcr(Path arquivo) throws Exception {
        try (InputStream in = Files.newInputStream(arquivo)) {
            return (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
        }
    }

    private static KeyStore p12(Path arquivo) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(arquivo)) {
            keyStore.load(in, "senha-teste".toCharArray());
        }
        return keyStore;
    }

    @Test
    void shouldWriteAllArtifactsWhenOutputDirectoryIsGiven() {
        assertThat(List.of(resultado.raiz(), resultado.ac(), resultado.signatario(), resultado.revogado(),
                resultado.lcrRaiz(), resultado.lcrAc(), resultado.yaml())).allMatch(Files::isRegularFile);
        assertThat(resultado.raiz().getFileName()).hasToString("raiz.pem");
        assertThat(resultado.ac().getFileName()).hasToString("ac.pem");
        assertThat(resultado.signatario().getFileName()).hasToString("signatario.p12");
        assertThat(resultado.revogado().getFileName()).hasToString("revogado.p12");
        assertThat(resultado.lcrRaiz().getFileName()).hasToString("lcr-raiz.crl");
        assertThat(resultado.lcrAc().getFileName()).hasToString("lcr-ac.crl");
        assertThat(resultado.yaml().getFileName()).hasToString("application-simulacao.yml");
    }

    @Test
    void shouldIssueSelfSignedRootAndIntermediateCaWhenGenerating() throws Exception {
        X509Certificate raiz = certificado(resultado.raiz());
        X509Certificate ac = certificado(resultado.ac());

        raiz.verify(raiz.getPublicKey());
        ac.verify(raiz.getPublicKey());
        assertThat(raiz.getBasicConstraints()).isGreaterThanOrEqualTo(0);
        assertThat(ac.getBasicConstraints()).isGreaterThanOrEqualTo(0);
        assertThat(raiz.getSubjectX500Principal().getName()).contains("SIMULACAO - SEM VALOR LEGAL");
        assertThat(ac.getSubjectX500Principal().getName()).contains("SIMULACAO - SEM VALOR LEGAL");
    }

    @Test
    void shouldIssueLeafEligibleForA3WhenAllowlistUsesGeneratedEntry() throws Exception {
        KeyStore keyStore = p12(resultado.signatario());
        X509Certificate folha = (X509Certificate) keyStore.getCertificate(GeradorPkiSimulada.ALIAS_SIGNATARIO);
        X509Certificate ac = certificado(resultado.ac());
        var allowlist = List.of(new AcceptedCertificatePolicy(resultado.politicaOid(), CertificateType.A3,
                resultado.issuerSha256()));

        ProfileResult perfil = IcpBrasilCertificateProfile.evaluate(folha, ac, allowlist, 1751328000L);

        assertThat(perfil).isInstanceOf(ProfileResult.Eligible.class);
        assertThat(((ProfileResult.Eligible) perfil).identity().value()).isEqualTo(GeradorPkiSimulada.CPF_PADRAO);
        assertThat(keyStore.isKeyEntry(GeradorPkiSimulada.ALIAS_SIGNATARIO)).isTrue();
        assertThat(keyStore.getCertificateChain(GeradorPkiSimulada.ALIAS_SIGNATARIO)).hasSize(3);
        assertThat(folha.getKeyUsage()[1]).isTrue();
        assertThat(folha.getSubjectX500Principal().getName()).contains("SIMULACAO - SEM VALOR LEGAL");
        assertThat(resultado.issuerSha256()).isEqualTo(IcpBrasilCertificateProfile.sha256Hex(ac));
    }

    @Test
    void shouldRevokeOnlySecondLeafWhenReadingIntermediateCrl() throws Exception {
        X509Certificate raiz = certificado(resultado.raiz());
        X509Certificate ac = certificado(resultado.ac());
        X509CRL lcrAc = lcr(resultado.lcrAc());
        X509CRL lcrRaiz = lcr(resultado.lcrRaiz());

        lcrAc.verify(ac.getPublicKey());
        lcrRaiz.verify(raiz.getPublicKey());
        assertThat(lcrAc.isRevoked(p12(resultado.revogado()).getCertificate(GeradorPkiSimulada.ALIAS_REVOGADO))).isTrue();
        assertThat(lcrAc.isRevoked(p12(resultado.signatario()).getCertificate(GeradorPkiSimulada.ALIAS_SIGNATARIO))).isFalse();
        assertThat(lcrRaiz.isRevoked(ac)).isFalse();
    }

    @Test
    void shouldWriteYamlSnippetWithPathsAndAllowlistWhenGenerating() throws Exception {
        String yaml = Files.readString(resultado.yaml());

        assertThat(yaml).contains("enabled: true")
                .contains(resultado.raiz().toUri().toString())
                .contains(resultado.ac().toUri().toString())
                .contains(resultado.lcrAc().toUri().toString())
                .contains(resultado.lcrRaiz().toUri().toString())
                .contains(resultado.politicaOid())
                .contains(resultado.issuerSha256());
    }

    @Test
    void shouldNotPointYamlUsageToProductJarsWhenGenerating() throws Exception {
        String yaml = Files.readString(resultado.yaml());

        assertThat(yaml).contains("--spring.profiles.active=simulacao")
                .doesNotContain("safira-rest.jar")
                .doesNotContain("safira-app");
    }

    @Test
    void shouldRejectCpfWhenCheckDigitsAreInvalid() {
        assertThatThrownBy(() -> Opcoes.padrao().comCpf("12345678900"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectPolicyOidWhenOutsideA3Branch() {
        assertThatThrownBy(() -> Opcoes.padrao().comPoliticaOid("2.16.76.1.2.1.1"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldGenerateFromCommandLineWhenOutputIsGiven(@TempDir Path destino) throws Exception {
        GeradorPkiSimulada.main(new String[]{"--saida", destino.toString(), "--senha", "senha-teste",
                "--politica", "2.16.76.1.2.3.42"});

        assertThat(destino.resolve("signatario.p12")).isRegularFile();
        assertThat(Files.readString(destino.resolve("application-simulacao.yml"))).contains("2.16.76.1.2.3.42");
        assertThat(p12(destino.resolve("signatario.p12")).isKeyEntry(GeradorPkiSimulada.ALIAS_SIGNATARIO)).isTrue();
    }
}
