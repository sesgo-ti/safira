/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreConfig;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;

/**
 * Liga o Safira à icpbrasil-truststore: a porta de confiança sobre o acervo carregado pela lib e o
 * filtro de destino dos downloads do DSS sobre a política de download da lib
 * ({@code icpbrasil-truststore.download-policy.*}). Sem estes beans os steps não sobem (falha fechada).
 */
@AutoConfiguration(after = TrustStoreAutoConfiguration.class, before = SafiraStepsAutoConfiguration.class)
public class SafiraIcpBrasilAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public FonteDeConfianca safiraFonteDeConfianca(TrustMaterialSource trustMaterialSource) {
        return new FonteDeConfiancaIcpBrasil(trustMaterialSource);
    }

    @Bean
    @ConditionalOnMissingBean
    public DestinationGuard safiraDestinationGuard(TrustStoreConfig trustStoreConfig) {
        return DownloadPolicyGuard.of(trustStoreConfig.getDownloadPolicy());
    }
}
