/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Aplicação do simulador (SEM VALOR LEGAL): a mesma API do Safira ({@code safira-rest}, política
 * 0.2.0) com a PKI simulada no lugar do acervo ICP-Brasil, sem rede e sem a icpbrasil-truststore.
 * Sem âncoras configuradas, a PKI é gerada na 1ª partida e reutilizada nas seguintes
 * ({@link PkiGeradaNaPartida}, {@link RepositorioPkiSimulada}).
 */
@SpringBootApplication
public class SimuladorApplication {

    public static void main(String[] args) {
        aplicacao().run(args);
    }

    /** Perfil com a configuração da aplicação ({@code application-simulador.yml}). */
    public static final String PERFIL = "simulador";

    /** A aplicação no perfil {@link #PERFIL}, com o inicializador que gera a PKI simulada na partida. */
    public static SpringApplication aplicacao() {
        SpringApplication aplicacao = new SpringApplication(SimuladorApplication.class);
        aplicacao.setAdditionalProfiles(PERFIL);
        aplicacao.addInitializers(new PkiGeradaNaPartida());
        return aplicacao;
    }
}
