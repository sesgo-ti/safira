/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.core.io.Resource;

import java.util.List;
import java.util.Objects;

/**
 * Modo simulação ({@code safira.simulacao.*}): confiança em raízes próprias no lugar do acervo
 * ICP-Brasil. Assinaturas produzidas assim não têm valor legal.
 *
 * @param enabled       liga o modo (desligado por padrão)
 * @param trustAnchors  bundle PEM com as raízes autoassinadas (obrigatório)
 * @param intermediates bundle PEM com ACs intermediárias (opcional)
 * @param crls          LCRs (DER ou PEM) usadas no lugar da consulta online (opcional)
 */
@ConfigurationProperties(prefix = "safira.simulacao")
public record SafiraSimulacaoProperties(boolean enabled, Resource trustAnchors, Resource intermediates,
                                        List<Resource> crls) {

    public SafiraSimulacaoProperties {
        crls = crls == null ? List.of() : crls.stream().filter(Objects::nonNull).toList();
    }
}
