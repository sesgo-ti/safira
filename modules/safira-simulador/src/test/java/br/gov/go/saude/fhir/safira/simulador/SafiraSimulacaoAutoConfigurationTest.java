/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

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
            assertThat(context).doesNotHaveBean(TrustMaterialSource.class);
        });
    }

    @Test
    void shouldProvideOnlySimulatedRootsWhenEnabled() {
        runner.withPropertyValues(habilitado(pki.raiz().toUri().toString())).run(context -> {
            assertThat(context).hasSingleBean(TrustMaterialSource.class);
            TrustMaterial material = context.getBean(TrustMaterialSource.class).current().orElseThrow();

            assertThat(material.anchors()).extracting(TrustAnchor::getTrustedCert)
                    .containsExactly(certificado(pki.raiz()));
            List<Certificate> acs = List.copyOf(material.intermediates().getCertificates(null));
            assertThat(acs).containsExactly(certificado(pki.ac()));
        });
    }

    @Test
    void shouldReplaceLibraryTrustMaterialSourceWhenEnabled() {
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(TrustStoreAutoConfiguration.class,
                        SafiraSimulacaoAutoConfiguration.class))
                .withPropertyValues("icpbrasil-truststore.bootstrap.enabled=false",
                        "icpbrasil-truststore.scheduling.enabled=false",
                        "icpbrasil-truststore.filesystem.base-dir=" + saida.resolve("acervo"))
                .withPropertyValues(habilitado(pki.raiz().toUri().toString()))
                .run(context -> {
                    assertThat(context).hasSingleBean(TrustMaterialSource.class);
                    assertThat(context.getBean(TrustMaterialSource.class).current().orElseThrow().anchors())
                            .extracting(TrustAnchor::getTrustedCert).containsExactly(certificado(pki.raiz()));
                });
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
}
