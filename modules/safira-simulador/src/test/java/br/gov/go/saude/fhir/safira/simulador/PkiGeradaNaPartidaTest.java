/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.mock.env.MockEnvironment;

import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class PkiGeradaNaPartidaTest {

    @TempDir
    Path diretorio;

    private GenericApplicationContext contexto(String... propriedades) {
        MockEnvironment ambiente = new MockEnvironment()
                .withProperty("safira.simulador.diretorio", diretorio.toString());
        for (String propriedade : propriedades) {
            String[] chaveValor = propriedade.split("=", 2);
            ambiente.setProperty(chaveValor[0], chaveValor[1]);
        }
        GenericApplicationContext contexto = new GenericApplicationContext();
        contexto.setEnvironment(ambiente);
        new PkiGeradaNaPartida().initialize(contexto);
        return contexto;
    }

    @Test
    void shouldNotGenerateWhenModeIsOff() {
        GenericApplicationContext contexto = contexto("safira.simulacao.enabled=false");

        assertThat(contexto.getBeanFactory().getBeanNamesForType(PkiPersistida.class)).isEmpty();
        assertThat(diretorio).isEmptyDirectory();
    }

    @Test
    void shouldNotGenerateWhenAnchorsAreConfigured() {
        GenericApplicationContext contexto = contexto("safira.simulacao.enabled=true",
                "safira.simulacao.trust-anchors=file:/tmp/raiz.pem");

        assertThat(contexto.getBeanFactory().getBeanNamesForType(PkiPersistida.class)).isEmpty();
    }

    @Test
    void shouldNotGenerateWhenCrlsAreConfigured() {
        GenericApplicationContext contexto = contexto("safira.simulacao.enabled=true",
                "safira.simulacao.crls[0]=file:/tmp/lcr.crl");

        assertThat(contexto.getBeanFactory().getBeanNamesForType(PkiPersistida.class)).isEmpty();
    }

    @Test
    void shouldPublishAnchorsAllowlistAndTsaPolicyWhenGenerating() {
        GenericApplicationContext contexto = contexto("safira.simulacao.enabled=true",
                "safira.simulacao.trust-anchors=");
        PkiPersistida pki = contexto.getBeanFactory().getBean(PkiPersistida.class);
        var ambiente = contexto.getEnvironment();

        assertThat(pki.raiz()).isRegularFile().hasParent(diretorio.toAbsolutePath().normalize());
        assertThat(ambiente.getProperty("safira.simulacao.trust-anchors")).isEqualTo(pki.raiz().toUri().toString());
        assertThat(ambiente.getProperty("safira.simulacao.intermediates")).isEqualTo(pki.ac().toUri().toString());
        assertThat(ambiente.getProperty("safira.policy.accepted-certificate-policies[0].oid")).isEqualTo(pki.politicaOid());
        assertThat(ambiente.getProperty("safira.policy.accepted-certificate-policies[0].issuer-sha256"))
                .isEqualTo(pki.issuerSha256());
        assertThat(ambiente.getProperty("safira.policy.tsa-policies.policies[0].oid")).isEqualTo(PkiIcpSimulada.POLITICA_TSA);
        assertThat(ambiente.getProperty("safira.policy.tsa-policies.policies[0].trust-store.reference"))
                .isEqualTo(pki.raiz().toUri().toString());
    }

    @Test
    void shouldUseDirectoryUnderUserHomeWhenNotConfigured() {
        Path home = Path.of(System.getProperty("user.home"));
        assertThat(home.toString()).endsWith(Path.of("target", "home").toString());
        GenericApplicationContext contexto = new GenericApplicationContext();
        contexto.setEnvironment(new MockEnvironment().withProperty("safira.simulacao.enabled", "true"));

        new PkiGeradaNaPartida().initialize(contexto);

        assertThat(contexto.getBeanFactory().getBean(PkiPersistida.class).diretorio())
                .isEqualTo(home.resolve(".safira-simulador").resolve("pki").toAbsolutePath().normalize());
    }
}
