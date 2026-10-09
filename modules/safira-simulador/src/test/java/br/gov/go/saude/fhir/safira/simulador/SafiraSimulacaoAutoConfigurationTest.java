/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.jades.CertificateValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplecertificatereport.SimpleCertificateReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.io.InputStream;
import java.nio.file.Files;
import java.net.InetAddress;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SafiraSimulacaoAutoConfigurationTest {

    @TempDir
    static Path saida;

    static Resultado pki;

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraSimulacaoAutoConfiguration.class));

    @BeforeAll
    static void gerar() {
        pki = GeradorPkiSimulada.gerar(saida, Opcoes.padrao());
    }

    static X509Certificate certificado(Path pem) throws Exception {
        try (InputStream in = Files.newInputStream(pem)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        }
    }

    private static String[] habilitado(String anchors) {
        return new String[]{"safira.simulacao.enabled=true", "safira.simulacao.trust-anchors=" + anchors,
                "safira.simulacao.intermediates=" + pki.ac().toUri()};
    }

    @Test
    void shouldNotRegisterBeansWhenModeIsDisabledByDefault() {
        runner.run(context -> {
            assertThat(context).hasNotFailed();
            assertThat(context).doesNotHaveBean(FonteDeConfianca.class);
            assertThat(context).doesNotHaveBean(DestinationGuard.class);
        });
    }

    @Test
    void shouldProvideOnlySimulatedRootsWhenEnabled() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).run(context -> {
            assertThat(context).hasSingleBean(FonteDeConfianca.class);
            AcervoDeConfianca acervo = context.getBean(FonteDeConfianca.class).atual().orElseThrow();

            assertThat(acervo.raizes()).containsExactly(certificado(pki.raiz()));
            assertThat(acervo.intermediarias()).containsExactly(certificado(pki.ac()));
            assertThat(acervo.geracao()).startsWith("simulacao-");
        });
    }

    @Test
    void shouldRefuseEveryDestinationWhenEnabled() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).run(context -> {
            DestinationGuard guard = context.getBean(DestinationGuard.class);

            assertThatThrownBy(() -> guard.check("lcr.example.com", InetAddress.getByAddress(new byte[]{8, 8, 8, 8})))
                    .isInstanceOf(IllegalStateException.class);
        });
    }

    @Test
    void shouldKeepApplicationDestinationGuardWhenProvided() {
        DestinationGuard daAplicacao = (host, address) -> {
        };
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString()))
                .withBean(DestinationGuard.class, () -> daAplicacao)
                .run(context -> assertThat(context.getBean(DestinationGuard.class)).isSameAs(daAplicacao));
    }

    @Test
    void shouldRegisterSimulationAdviceWhenEnabled() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).run(context ->
                assertThat(context).hasSingleBean(AvisoSimulacaoAdvice.class));
    }

    @Test
    void shouldNotRegisterSimulationAdviceWhenModeIsDisabled() {
        runner.run(context -> assertThat(context).doesNotHaveBean(AvisoSimulacaoAdvice.class));
    }

    @Test
    void shouldFailStartupWhenTrustAnchorsAreMissing() {
        runner.withPropertyValues("safira.simulacao.enabled=true").run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("safira.simulacao.trust-anchors");
        });
    }

    @Test
    void shouldFailStartupWhenTrustAnchorsFileDoesNotExist() {
        runner.withPropertyValues(habilitado(saida.resolve("inexistente.pem").toUri().toString())).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("inexistente.pem");
        });
    }

    @Test
    void shouldFailStartupWhenTrustAnchorsBundleIsEmpty() throws Exception {
        Path vazio = Files.writeString(saida.resolve("vazio.pem"), "");

        runner.withPropertyValues(habilitado(vazio.toUri().toString())).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("nenhum certificado");
        });
    }

    @Test
    void shouldFailStartupWhenAnchorIsNotSelfSignedCa() {
        runner.withPropertyValues(habilitado(pki.ac().toUri().toString())).run(context -> {
            assertThat(context).hasFailed();
            assertThat(context.getStartupFailure()).rootCause().hasMessageContaining("autoassinad");
        });
    }

    private static X509Certificate folha(Path p12, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (InputStream in = Files.newInputStream(p12)) {
            keyStore.load(in, pki.senha().toCharArray());
        }
        return (X509Certificate) keyStore.getCertificate(alias);
    }

    private static SimpleCertificateReport relatorio(CertificateVerifierFactory factory, X509Certificate folha)
            throws Exception {
        CommonCertificateVerifier verifier = factory.create(CertificateVerifierFactory.acervo(
                List.of(certificado(pki.raiz())), List.of(certificado(pki.ac()))), List.of());
        return new CertificateValidationService().validate(folha, List.of(), verifier).getSimpleReport();
    }

    private static String[] comLcrs() {
        return new String[]{"safira.simulacao.crls[0]=" + pki.lcrRaiz().toUri(),
                "safira.simulacao.crls[1]=" + pki.lcrAc().toUri()};
    }

    @Test
    void shouldKeepOnlineVerifierFactoryWhenCrlsAreAbsent() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).run(context ->
                assertThat(context).doesNotHaveBean(CertificateVerifierFactory.class));
    }

    @Test
    void shouldKeepOnlineVerifierFactoryWhenCrlsAreBlank() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString()))
                .withPropertyValues("safira.simulacao.crls=")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context).doesNotHaveBean(CertificateVerifierFactory.class);
                });
    }

    @Test
    void shouldDecideRevocationFromLocalCrlsWhenConfigured() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).withPropertyValues(comLcrs())
                .run(context -> {
                    CertificateVerifierFactory factory = context.getBean(CertificateVerifierFactory.class);
                    X509Certificate valido = folha(pki.signatario(), GeradorPkiSimulada.ALIAS_SIGNATARIO);
                    X509Certificate revogado = folha(pki.revogado(), GeradorPkiSimulada.ALIAS_REVOGADO);

                    SimpleCertificateReport okReport = relatorio(factory, valido);
                    SimpleCertificateReport revokedReport = relatorio(factory, revogado);

                    String idValido = new CertificateToken(valido).getDSSIdAsString();
                    String idRevogado = new CertificateToken(revogado).getDSSIdAsString();
                    assertThat(okReport.getCertificateIndication(idValido)).isEqualTo(Indication.PASSED);
                    assertThat(revokedReport.getCertificateSubIndication(idRevogado)).isEqualTo(SubIndication.REVOKED_NO_POE);
                });
    }

    @Test
    void shouldFailStartupWhenCrlIsUnreadable() throws Exception {
        Path invalida = Files.writeString(saida.resolve("invalida.crl"), "nao e uma LCR");

        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString()))
                .withPropertyValues("safira.simulacao.crls[0]=" + invalida.toUri())
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure()).hasStackTraceContaining("LCR ilegível").hasStackTraceContaining("invalida.crl");
                });
    }
}
