/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Configuração do perfil JAdES (política 2.0.0).
 *
 * <p>{@code safira.jades.signing.target-level} define o nível baseline alvo quando a
 * estratégia de carimbo é {@code tsa} (ETSI TS 119 182-1 §6.3 — níveis cumulativos):
 *
 * <ul>
 *   <li>{@code B-T} — carimbo de assinatura ({@code sigTst}) apenas (padrão);</li>
 *   <li>{@code B-LT} — LTV: material completo de validação embutido
 *       ({@code xVals}/{@code rVals}/{@code tstVD});</li>
 *   <li>{@code B-LTA} — arquivamento: acrescenta carimbo de arquivo ({@code arcTst}).</li>
 * </ul>
 *
 * <p>Na estratégia {@code iat} a assinatura permanece B-B independentemente deste valor
 * (sem carimbo TSA não há B-T e, por consequência, nenhum nível superior).
 */
@ConfigurationProperties(prefix = "safira.jades")
public record SafiraJadesProperties(@DefaultValue SigningProps signing) {

    public SafiraJadesProperties {
        if (signing == null) {
            signing = new SigningProps(TargetLevel.B_T);
        }
    }

    public record SigningProps(@DefaultValue("B-T") TargetLevel targetLevel) {
    }

    public enum TargetLevel {
        B_T, B_LT, B_LTA
    }
}
