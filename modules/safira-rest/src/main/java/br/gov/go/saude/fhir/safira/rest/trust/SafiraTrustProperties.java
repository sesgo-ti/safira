/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.trust;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuração de raiz de confiança personalizada ({@code safira.trust.*}).
 *
 * @param customRootsDir diretório com os certificados públicos (.pem/.cer/.crt/.der) que
 *                        substituem o acervo ICP-Brasil como fonte de confiança; sem default,
 *                        ausente desativa inteiramente essa funcionalidade
 */
@ConfigurationProperties(prefix = "safira.trust")
public record SafiraTrustProperties(String customRootsDir) {
}
