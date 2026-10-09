/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador.sistema;

import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.rest.service.JadesSigningSystemTest;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Optional;

/**
 * Safira fora do modo simulação: no lugar do acervo ICP-Brasil, um acervo com outra raiz (a da PKI
 * de teste do {@code safira-jades}), que não contém a raiz simulada, e nenhum destino de rede.
 */
@TestConfiguration(proxyBeanMethods = false)
public class ModoIcpBrasilDeTeste {

    @Bean
    FonteDeConfianca fonteDeConfiancaDeOutraRaiz() {
        Optional<AcervoDeConfianca> acervo = Optional.of(new AcervoDeConfianca("teste-outra-raiz",
                List.of(JadesSigningSystemTest.PKI.caCert), List.of()));
        return () -> acervo;
    }

    @Bean
    DestinationGuard destinoBloqueadoDeTeste() {
        return (host, address) -> {
            throw new IllegalStateException("Sem rede nos testes do simulador: " + host);
        };
    }
}
