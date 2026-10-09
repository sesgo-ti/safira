/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.app.icpbrasil.FonteDeConfiancaIcpBrasil;
import br.gov.go.saude.fhir.safira.cli.Cli.Resultado;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import br.gov.go.saude.fhir.safira.simulador.FonteDeConfiancaSimulada;
import br.gov.go.saude.fhir.safira.simulador.PkiPersistida;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/** Só uma fonte de confiança por modo: os modos nunca se misturam, nem por configuração externa. */
class ModoExclusivoTest {

    @TempDir
    Path diretorio;

    @AfterEach
    void limpar() {
        System.clearProperty("safira.simulacao.enabled");
    }

    private Path config(String yaml) throws Exception {
        return Cli.escrever(diretorio.resolve("config.yml"), yaml);
    }

    private Resultado validar(String modo, Path config) throws Exception {
        Path bundle = Cli.exemplo(diretorio, "bundle.json");
        String[] base = {"validar", "--modo", modo, "--signature", bundle.toString(), "--bundle", bundle.toString(),
                "--provenance", bundle.toString(), "--config", config.toString()};
        if (!"simulacao".equals(modo)) {
            return Cli.executar(base);
        }
        String[] argumentos = Arrays.copyOf(base, base.length + 2);
        argumentos[base.length] = "--pki-dir";
        argumentos[base.length + 1] = diretorio.resolve("pki").toString();
        return Cli.executar(argumentos);
    }

    @Test
    void shouldRejectForeignTrustSourceInIcpBrasilMode() throws Exception {
        Resultado resultado = validar("icpbrasil", config("""
                spring:
                  main:
                    sources: br.gov.go.saude.fhir.safira.cli.FontesIntrusas$UmaFonteQualquer
                """));

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains("única fonte de confiança");
    }

    @Test
    void shouldRejectSecondTrustSourceInSimulationMode() throws Exception {
        Resultado resultado = validar("simulacao", config("""
                spring:
                  main:
                    sources: br.gov.go.saude.fhir.safira.cli.FontesIntrusas$FontePrimaria
                """));

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
        assertThat(resultado.err()).contains("única fonte de confiança");
    }

    @Test
    void shouldRejectIcpBrasilSourcesInSimulationMode() throws Exception {
        Resultado resultado = validar("simulacao", config("""
                spring:
                  main:
                    sources: >-
                      br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration,
                      br.gov.go.saude.fhir.safira.app.icpbrasil.SafiraIcpBrasilAutoConfiguration
                icpbrasil-truststore:
                  filesystem:
                    base-dir: %s
                """.formatted(diretorio.resolve("acervo"))));

        assertThat(resultado.saida()).isEqualTo(CodigosDeSaida.USO);
        assertThat(resultado.out()).isEmpty();
    }

    @Test
    void shouldStayIcpBrasilWhenSimulationSourcesAndProfileAreAdded() throws Exception {
        Resultado resultado = validar("icpbrasil", config("""
                spring:
                  main:
                    sources: br.gov.go.saude.fhir.safira.simulador.SafiraSimulacaoAutoConfiguration
                  profiles:
                    active: simulacao,simulador
                safira:
                  simulacao:
                    enabled: true
                """));

        assertThat(resultado.saida()).isNotEqualTo(CodigosDeSaida.SUCESSO);
        assertThat(resultado.out() + resultado.err()).doesNotContain(AvisoSimulacaoAdvice.TEXTO)
                .doesNotContain("MODO SIMULAÇÃO");
    }

    @Test
    void shouldApplyTrustDownloadTimeoutToLibrary() {
        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.ICPBRASIL, null, null, 45, false)) {
            TrustStoreConfig config = contexto.aplicacao().getBean(TrustStoreConfig.class);

            assertThat(config.getNetwork().getDownloadTimeoutSeconds()).isEqualTo(45);
        }
    }

    @Test
    void shouldUseShortTrustDownloadDefaultsInCli() {
        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.ICPBRASIL, null, null, false)) {
            TrustStoreConfig config = contexto.aplicacao().getBean(TrustStoreConfig.class);

            assertThat(config.getNetwork().getDownloadTimeoutSeconds()).isEqualTo(30);
            assertThat(config.getNetwork().getMaxRetries()).isEqualTo(1);
        }
    }

    @Test
    void shouldKeepOnlySimulatedTrustInSimulationMode() {
        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.SIMULACAO, diretorio.resolve("pki"), null, false)) {
            Map<String, FonteDeConfianca> fontes = contexto.aplicacao().getBeansOfType(FonteDeConfianca.class);

            assertThat(fontes).hasSize(1);
            assertThat(fontes.values().iterator().next()).isInstanceOf(FonteDeConfiancaSimulada.class);
            assertThat(contexto.aplicacao().getBeansOfType(TrustMaterialSource.class)).isEmpty();
            assertThat(contexto.aplicacao().getBeansOfType(PkiPersistida.class)).hasSize(1);
        }
    }

    @Test
    void shouldKeepOnlyIcpBrasilTrustEvenWhenSimulationIsEnabledBySystemProperty() {
        System.setProperty("safira.simulacao.enabled", "true");

        try (ContextoSafira contexto = ContextoSafira.iniciar(Modo.ICPBRASIL, null, null, false)) {
            Map<String, FonteDeConfianca> fontes = contexto.aplicacao().getBeansOfType(FonteDeConfianca.class);

            assertThat(fontes).hasSize(1);
            assertThat(fontes.values().iterator().next()).isInstanceOf(FonteDeConfiancaIcpBrasil.class);
            assertThat(contexto.aplicacao().getBeansOfType(PkiPersistida.class)).isEmpty();
        }
    }
}
