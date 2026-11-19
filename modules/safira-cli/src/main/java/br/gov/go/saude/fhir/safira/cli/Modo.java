/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.app.icpbrasil.FonteDeConfiancaIcpBrasil;
import br.gov.go.saude.fhir.safira.app.icpbrasil.SafiraIcpBrasilAutoConfiguration;
import br.gov.go.saude.fhir.safira.simulador.FonteDeConfiancaSimulada;
import br.gov.go.saude.fhir.safira.simulador.SafiraSimulacaoAutoConfiguration;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import picocli.CommandLine.ITypeConverter;
import picocli.CommandLine.TypeConversionException;

import java.util.List;

/**
 * Modo de confiança de uma execução da CLI. Cada modo tem uma única fonte de confiança e exclui as
 * auto-configurações do outro: os modos nunca se misturam no mesmo processo.
 */
public enum Modo {

    /** Acervo ICP-Brasil da icpbrasil-truststore (adaptador do {@code safira-app}). Padrão. */
    ICPBRASIL("icpbrasil", FonteDeConfiancaIcpBrasil.class, false,
            List.of(SafiraSimulacaoAutoConfiguration.class.getName())),

    /** PKI simulada persistida do {@code safira-simulador}, sem rede e SEM VALOR LEGAL. */
    SIMULACAO("simulacao", FonteDeConfiancaSimulada.class, true,
            List.of(TrustStoreAutoConfiguration.class.getName(), SafiraIcpBrasilAutoConfiguration.class.getName()));

    private final String nome;
    private final Class<? extends FonteDeConfianca> fonte;
    private final boolean simulacao;
    private final List<String> excluidas;

    Modo(String nome, Class<? extends FonteDeConfianca> fonte, boolean simulacao, List<String> excluidas) {
        this.nome = nome;
        this.fonte = fonte;
        this.simulacao = simulacao;
        this.excluidas = excluidas;
    }

    /** Nome na linha de comando e perfil do Spring ({@code safira-cli-<nome>.yml}). */
    public String nome() {
        return nome;
    }

    /** Tipo da única fonte de confiança admitida no modo. */
    public Class<? extends FonteDeConfianca> fonte() {
        return fonte;
    }

    /** Valor forçado de {@code safira.simulacao.enabled}. */
    public boolean simulacao() {
        return simulacao;
    }

    /** Auto-configurações do outro modo, excluídas do contexto. */
    public List<String> excluidas() {
        return excluidas;
    }

    /** Conversor de {@code --modo}: só os nomes em minúsculas. */
    static final class Conversor implements ITypeConverter<Modo> {

        @Override
        public Modo convert(String valor) {
            for (Modo modo : values()) {
                if (modo.nome.equals(valor)) {
                    return modo;
                }
            }
            throw new TypeConversionException("modo desconhecido '" + valor + "' (use icpbrasil ou simulacao)");
        }
    }
}
