/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.config.TrustStoreAutoConfiguration;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;

import java.security.cert.TrustAnchor;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Modo simulação: substitui o acervo ICP-Brasil pelas raízes de {@code safira.simulacao.*}, sem
 * misturá-los. Os steps não mudam; só a fonte de confiança (e, com LCRs locais, a de revogação).
 * Roda antes da auto-configuração da icpbrasil-truststore e dos steps, cujos beans são
 * {@code @ConditionalOnMissingBean}.
 */
@AutoConfiguration(before = {TrustStoreAutoConfiguration.class, SafiraStepsAutoConfiguration.class})
@ConditionalOnProperty(prefix = "safira.simulacao", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SafiraSimulacaoProperties.class)
public class SafiraSimulacaoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SafiraSimulacaoAutoConfiguration.class);

    @Bean
    public TrustMaterialSource simulacaoTrustMaterialSource(SafiraSimulacaoProperties propriedades) {
        TrustMaterial material = MaterialSimulado.carregar(propriedades);
        String raizes = material.anchors().stream()
                .map(TrustAnchor::getTrustedCert)
                .map(raiz -> raiz.getSubjectX500Principal().getName())
                .collect(Collectors.joining("; "));
        log.warn("""

                ************************************************************************
                *  MODO SIMULAÇÃO ATIVO (safira.simulacao.enabled=true)                 *
                *  Raízes de confiança PRÓPRIAS no lugar do acervo ICP-Brasil.          *
                *  As assinaturas NÃO têm validade jurídica ICP-Brasil.                 *
                *  Nunca use este modo em produção.                                     *
                ************************************************************************
                Raízes simuladas: {}""", raizes);
        Optional<TrustMaterial> atual = Optional.of(material);
        return () -> atual;
    }

    /**
     * Com {@code safira.simulacao.crls}, a revogação vem só das LCRs locais (sem rede); sem elas,
     * vale a fábrica online padrão de {@link SafiraStepsAutoConfiguration}.
     */
    @Configuration(proxyBeanMethods = false)
    @Conditional(LcrsSimuladas.Configuradas.class)
    static class LcrsLocaisConfiguration {

        @Bean
        @ConditionalOnMissingBean
        CertificateVerifierFactory simulacaoCertificateVerifierFactory(SafiraSimulacaoProperties propriedades) {
            return CertificateVerifierFactory.offline(null,
                    LcrsSimuladas.fonte(propriedades.crls(), MaterialSimulado.conferidos(propriedades)));
        }
    }
}
