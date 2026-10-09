/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Opcoes;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.ApplicationContextInitializer;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Gera a PKI simulada na partida da aplicação do simulador quando o modo está ligado e nenhuma
 * âncora ou LCR foi configurada: grava os artefatos em {@code safira.simulador.diretorio} (padrão:
 * diretório temporário novo; a PKI é efêmera), publica âncoras, ACs, allowlist e política TSA como
 * propriedades de maior precedência e registra o {@link Resultado}, cujas fontes OCSP, LCR e TSA em
 * memória a {@link SafiraSimulacaoAutoConfiguration} usa. As âncoras seguem o carregamento validado
 * de {@code safira.simulacao.trust-anchors} (marca, chave, validade).
 */
public final class PkiGeradaNaPartida implements ApplicationContextInitializer<ConfigurableApplicationContext> {

    static final String FONTE = "safiraSimuladorPkiGerada";
    static final String DIRETORIO = "safira.simulador.diretorio";

    private static final Logger log = LoggerFactory.getLogger(PkiGeradaNaPartida.class);

    @Override
    public void initialize(ConfigurableApplicationContext contexto) {
        ConfigurableEnvironment ambiente = contexto.getEnvironment();
        if (!"true".equalsIgnoreCase(ambiente.getProperty("safira.simulacao.enabled"))
                || StringUtils.hasText(ambiente.getProperty("safira.simulacao.trust-anchors"))
                || lcrsConfiguradas(ambiente)) {
            return;
        }
        Resultado pki = GeradorPkiSimulada.gerar(diretorio(ambiente), Opcoes.padrao());
        ambiente.getPropertySources().addFirst(new MapPropertySource(FONTE, propriedades(pki)));
        contexto.getBeanFactory().registerSingleton("pkiSimuladaGerada", pki);
        log.warn("""

                PKI simulada (SEM VALOR LEGAL) gerada na partida em {}
                  senha dos PKCS#12 : {}
                  aliases           : {} (válido), {} (revogado)
                  política (OID)    : {}""", pki.raiz().getParent(), pki.senha(),
                GeradorPkiSimulada.ALIAS_SIGNATARIO, GeradorPkiSimulada.ALIAS_REVOGADO, pki.politicaOid());
    }

    private static boolean lcrsConfiguradas(ConfigurableEnvironment ambiente) {
        return Binder.get(ambiente).bind("safira.simulacao.crls", Bindable.listOf(String.class))
                .map(lista -> lista.stream().anyMatch(StringUtils::hasText))
                .orElse(false);
    }

    private static Path diretorio(ConfigurableEnvironment ambiente) {
        String configurado = ambiente.getProperty(DIRETORIO);
        try {
            return StringUtils.hasText(configurado) ? Path.of(configurado)
                    : Files.createTempDirectory("safira-simulador-pki-");
        } catch (IOException e) {
            throw new UncheckedIOException("Falha ao criar o diretório da PKI simulada", e);
        }
    }

    private static Map<String, Object> propriedades(Resultado pki) {
        Map<String, Object> propriedades = new LinkedHashMap<>();
        propriedades.put("safira.simulacao.trust-anchors", pki.raiz().toUri().toString());
        propriedades.put("safira.simulacao.intermediates", pki.ac().toUri().toString());
        propriedades.put("safira.policy.accepted-certificate-policies[0].oid", pki.politicaOid());
        propriedades.put("safira.policy.accepted-certificate-policies[0].type", "A3");
        propriedades.put("safira.policy.accepted-certificate-policies[0].issuer-sha256", pki.issuerSha256());
        // TSA simulada emitida pela mesma AC: a âncora do carimbo é a raiz simulada.
        propriedades.put("safira.policy.tsa-policies.version", "1.0.0");
        propriedades.put("safira.policy.tsa-policies.policies[0].oid", PkiIcpSimulada.POLITICA_TSA);
        propriedades.put("safira.policy.tsa-policies.policies[0].max-accuracy-seconds", "1");
        propriedades.put("safira.policy.tsa-policies.policies[0].trust-store.reference", pki.raiz().toUri().toString());
        return propriedades;
    }
}
