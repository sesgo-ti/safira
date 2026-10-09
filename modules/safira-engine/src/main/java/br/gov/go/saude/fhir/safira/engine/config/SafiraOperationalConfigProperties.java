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
     * @param ocspCacheTtl  Tempo de vida (segundos) para respostas OCSP em cache. Padrão: 3600. Intervalo: [300, 86400].
     * @param crlCacheTtl   Tempo de vida (segundos) para listas CRL em cache. Padrão: 3600. Intervalo: [300, 86400].
     * @param ocspTimeout   Timeout (segundos) para consultas OCSP. Padrão: 20. Intervalo: [5, 120].
     * @param crlTimeout    Timeout (segundos) para download de CRL. Padrão: 20. Intervalo: [5, 120].
     * @param tsaTimeout    Timeout (segundos) para comunicação com o serviço TSA. Padrão: 20. Intervalo: [5, 120].
     * @param maxRetries    Número máximo de tentativas em caso de falha de rede. Padrão: 3. Intervalo: [1, 5].
     * @param retryInterval Intervalo (segundos) entre tentativas de retry. Padrão: 2. Intervalo: [1, 10].
     * @param tsaUrl        URL do serviço TSA (RFC 3161). Obrigatória quando a estratégia de timestamp é TSA. Deve iniciar com https://.
     * @param tsaUsername   (Opcional) Usuário para autenticação HTTP Basic no serviço TSA.
     * @param tsaPassword   (Opcional) Senha para autenticação HTTP Basic no serviço TSA.
     */
    public record VerificationProps(
            @DefaultValue("3600") Integer ocspCacheTtl,
            @DefaultValue("3600") Integer crlCacheTtl,
            @DefaultValue("20")   Integer ocspTimeout,
            @DefaultValue("20")   Integer crlTimeout,
            @DefaultValue("20")   Integer tsaTimeout,
            @DefaultValue("3")    Integer maxRetries,
            @DefaultValue("2")    Integer retryInterval,
            String tsaUrl,
            String tsaUsername,
            String tsaPassword
    ) {}

    // -------------------------------------------------------------------------
    // Limites de segurança para processamento de Bundles FHIR
    // -------------------------------------------------------------------------

    /**
     * @param maxEntriesBundle        Número máximo de entradas no Bundle. Padrão: 1000. Intervalo: [100, 10000].
     * @param maxBundleSize           Tamanho máximo do Bundle em bytes. Padrão: 52428800 (50 MB). Intervalo: [1048576, 209715200].
     * @param timoutVerificationBundle Timeout (segundos) para verificação do Bundle. Padrão: 10. Intervalo: [5, 300].
     */
    public record SecurityLimitsProps(
            @DefaultValue("1000")        Integer maxEntriesBundle,
            @DefaultValue("52428800")    Integer maxBundleSize,
            @DefaultValue("10")          Integer timoutVerificationBundle
    ) {}
}
