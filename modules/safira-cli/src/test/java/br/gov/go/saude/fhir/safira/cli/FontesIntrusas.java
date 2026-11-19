/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;

import java.util.Optional;

/** Fontes de confiança alheias ao modo, injetadas por {@code spring.main.sources} nos testes do guarda. */
public final class FontesIntrusas {

    private FontesIntrusas() {
    }

    /** Uma fonte qualquer: no modo icpbrasil, ocupa o lugar do adaptador ({@code @ConditionalOnMissingBean}). */
    @Configuration(proxyBeanMethods = false)
    public static class UmaFonteQualquer {

        @Bean
        FonteDeConfianca fonteIntrusa() {
            return Optional::empty;
        }
    }

    /** Segunda fonte {@code @Primary}: o Spring a escolhe e a partida não falha sozinha. */
    @Configuration(proxyBeanMethods = false)
    public static class FontePrimaria {

        @Bean
        @Primary
        FonteDeConfianca fontePrimaria() {
            return Optional::empty;
        }
    }
}
