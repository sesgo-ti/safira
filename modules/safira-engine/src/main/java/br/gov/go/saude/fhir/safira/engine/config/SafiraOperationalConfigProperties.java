/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Propriedades de configuração operacional do engine de assinatura digital.
 * <p>
 * Mapeadas a partir do prefixo {@code safira.operational} no {@code application.yml}
 * de qualquer consumidor Spring Boot que inclua o {@code safira-engine} como dependência.
 * <p>
 * (padrão Spring Boot AutoConfiguration), sem necessidade de declaração manual pelo consumidor.
 */
@ConfigurationProperties(prefix = "safira.operational")
public record SafiraOperationalConfigProperties(

        @DefaultValue VerificationProps verification,
        @DefaultValue SecurityLimitsProps security

) {

    // -------------------------------------------------------------------------
    // Verificação: OCSP, CRL e TSA
    // -------------------------------------------------------------------------

    /**
     * @param ocspTimeout   Timeout (segundos) para consultas OCSP. Padrão: 20. Intervalo: [5, 120].
     * @param crlTimeout    Timeout (segundos) para download de CRL. Padrão: 20. Intervalo: [5, 120].
     * @param tsaTimeout    Timeout (segundos) para comunicação com o serviço TSA. Padrão: 20. Intervalo: [5, 120].
     * @param tsaUrl        URL do serviço TSA (RFC 3161). Obrigatória quando a estratégia de timestamp é TSA. Deve iniciar com https://.
     */
    public record VerificationProps(
            @DefaultValue("20")   Integer ocspTimeout,
            @DefaultValue("20")   Integer crlTimeout,
            @DefaultValue("20")   Integer tsaTimeout,
            String tsaUrl
    ) {}

    // -------------------------------------------------------------------------
    // Limites de segurança para processamento de Bundles FHIR
    // -------------------------------------------------------------------------

    /**
     * @param maxEntriesBundle        Número máximo de entradas no Bundle. Padrão: 1000. Intervalo: [100, 10000].
     * @param maxBundleSize           Tamanho máximo do Bundle em bytes. Padrão: 52428800 (50 MB). Intervalo: [1048576, 209715200].
     */
    public record SecurityLimitsProps(
            @DefaultValue("1000")        Integer maxEntriesBundle,
            @DefaultValue("52428800")    Integer maxBundleSize
    ) {}
}
