/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest;

import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;

import java.util.Optional;

/**
 * Aplicação mínima dos testes do {@code safira-rest}: só as auto-configurações, como numa aplicação
 * consumidora, com as portas que a aplicação fornece — acervo vazio (os testes o substituem por
 * {@code @MockitoBean}) e nenhum destino de rede permitido.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
public class SafiraRestTestApplication {

    @Bean
    FonteDeConfianca fonteDeConfiancaDeTeste() {
        return Optional::empty;
    }

    @Bean
    DestinationGuard destinoBloqueadoDeTeste() {
        return (host, address) -> {
            throw new IllegalStateException("Sem rede nos testes do safira-rest: " + host);
        };
    }
}
