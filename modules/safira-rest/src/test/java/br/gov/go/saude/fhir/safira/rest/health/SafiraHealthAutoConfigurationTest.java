/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.health;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.testkit.CertificadosIcpBrasilReais;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SafiraHealthAutoConfigurationTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(SafiraHealthAutoConfiguration.class));

    private static VerificadoresDss verificadores(FonteDeConfianca fonte) {
        return new VerificadoresDss(fonte, CertificateVerifierFactory.offline(null, null));
    }

    @Test
    void shouldRegisterIndicatorWhenVerificadoresDssBeanExists() {
        runner.withBean(VerificadoresDss.class, () -> verificadores(Optional::empty))
                .run(context -> assertThat(context).hasSingleBean(FonteDeConfiancaHealthIndicator.class)
                        .hasBean("fonteDeConfianca"));
    }

    @Test
    void shouldNotRegisterIndicatorWhenVerificadoresDssBeanIsMissing() {
        runner.run(context -> assertThat(context).doesNotHaveBean(FonteDeConfiancaHealthIndicator.class));
    }

    @Test
    void shouldReportDownWhenNoRootOfAcervoIsUsableByDss() {
        AcervoDeConfianca soV7 = new AcervoDeConfianca("v7", List.of(CertificadosIcpBrasilReais.raizV7()),
                List.of(PkiIcpSimulada.criar().ac()));

        runner.withBean(VerificadoresDss.class, () -> verificadores(() -> Optional.of(soV7)))
                .run(context -> assertThat(context.getBean(FonteDeConfiancaHealthIndicator.class).health().getStatus())
                        .isEqualTo(Status.DOWN));
    }

    @Test
    void shouldReportUpWhenAcervoHasUsableRootBesidesUnsupportedOne() {
        PkiIcpSimulada pki = PkiIcpSimulada.criar();
        AcervoDeConfianca misto = new AcervoDeConfianca("v7", List.of(CertificadosIcpBrasilReais.raizV7(), pki.raiz()),
                List.of(pki.ac()));

        runner.withBean(VerificadoresDss.class, () -> verificadores(() -> Optional.of(misto)))
                .run(context -> assertThat(context.getBean(FonteDeConfiancaHealthIndicator.class).health().getStatus())
                        .isEqualTo(Status.UP));
    }
}
