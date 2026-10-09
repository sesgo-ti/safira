/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSourceFactory;
import br.gov.go.saude.fhir.safira.simulador.GeradorPkiSimulada.Resultado;
import br.gov.go.saude.fhir.safira.steps.config.SafiraStepsAutoConfiguration;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Modo simulação: implementa a porta {@link FonteDeConfianca} com as raízes de
 * {@code safira.simulacao.*}, no lugar do acervo ICP-Brasil e sem misturá-los. Os steps não mudam;
 * só trocam as fontes de confiança, revogação e carimbo:
 * <ul>
 *   <li>revogação: LCRs locais (PKI em arquivos) ou OCSP e LCR em memória da PKI gerada na partida
 *       ({@link PkiGeradaNaPartida}); sem nenhuma delas, as fontes online do DSS presas ao
 *       {@link DestinationGuard} padrão, que recusa todo destino;</li>
 *   <li>carimbo do tempo: TSA em memória da PKI gerada na partida; com PKI em arquivos, indisponível
 *       ({@code TSA.UNAVAILABLE}). A TSA online nunca é usada.</li>
 * </ul>
 * Roda antes dos steps, cujos beans são {@code @ConditionalOnMissingBean}.
 */
@AutoConfiguration(before = SafiraStepsAutoConfiguration.class)
@ConditionalOnProperty(prefix = "safira.simulacao", name = "enabled", havingValue = "true")
@EnableConfigurationProperties(SafiraSimulacaoProperties.class)
public class SafiraSimulacaoAutoConfiguration {

    private static final Logger log = LoggerFactory.getLogger(SafiraSimulacaoAutoConfiguration.class);

    @Bean
    public FonteDeConfianca simulacaoFonteDeConfianca(SafiraSimulacaoProperties propriedades) {
        FonteDeConfianca fonte = MaterialSimulado.carregar(propriedades);
        AcervoDeConfianca acervo = fonte.atual().orElseThrow();
        String raizes = acervo.raizes().stream()
                .map(raiz -> raiz.getSubjectX500Principal().getName())
                .collect(Collectors.joining("; "));
        log.warn("""

                ************************************************************************
                *  MODO SIMULAÇÃO ATIVO (safira.simulacao.enabled=true)                 *
                *  Raízes de confiança PRÓPRIAS no lugar do acervo ICP-Brasil.          *
                *  As assinaturas NÃO têm validade jurídica ICP-Brasil.                 *
                *  Nunca use este modo em produção.                                     *
                ************************************************************************
                Raízes simuladas: {} (geração {})""", raizes, acervo.geracao());
        return fonte;
    }

    /** Sem rede no modo simulação: revogação e carimbo vêm de LCRs locais ou das fontes em memória. */
    @Bean
    @ConditionalOnMissingBean
    public DestinationGuard simulacaoDestinationGuard() {
        return (host, address) -> {
            throw new IllegalStateException("Modo simulação sem rede: destino recusado (" + host + ").");
        };
    }

    /**
     * Carimbo do tempo sem rede: com a PKI gerada na partida, a TSA em memória do testkit; sem ela (PKI
     * em arquivos), toda requisição de carimbo falha como TSA indisponível ({@code TSA.UNAVAILABLE}). A
     * {@code tsa-url} configurada nunca é contatada.
     */
    @Bean
    @ConditionalOnMissingBean
    public TspSourceFactory simulacaoTspSourceFactory(ObjectProvider<Resultado> pkiGerada) {
        Resultado pki = pkiGerada.getIfAvailable();
        if (pki != null) {
            return (tsaUrl, timeoutSeconds, policyOid) -> pki.pki().fonteTsp();
        }
        return (tsaUrl, timeoutSeconds, policyOid) -> {
            throw new DSSExternalResourceException("Modo simulação sem rede: sem TSA em memória (PKI em arquivos).");
        };
    }

    /** Marca o sucesso de {@code /validar} como simulação (sem validade jurídica ICP-Brasil). */
    @Bean
    public AvisoSimulacaoAdvice avisoSimulacaoAdvice() {
        return new AvisoSimulacaoAdvice();
    }

    /**
     * No modo simulação a allowlist {@code safira.policy.accepted-certificate-policies} precisa
     * fixar o emissor ({@code issuer-sha256}) de cada política: sem ele o startup falha, em vez de
     * recusar cada requisição. Só confere quando a política dos steps está no contexto.
     */
    @Bean
    SmartInitializingSingleton simulacaoAllowlistComEmissor(ObjectProvider<SafiraPolicyProperties> politica) {
        return () -> politica.ifAvailable(SafiraSimulacaoAutoConfiguration::exigirEmissores);
    }

    static void exigirEmissores(SafiraPolicyProperties politica) {
        List<AcceptedCertificatePolicy> allowlist = politica.acceptedCertificatePolicies();
        if (allowlist.isEmpty() || allowlist.stream().anyMatch(entrada -> !StringUtils.hasText(entrada.issuerSha256()))) {
            throw new IllegalStateException("Modo simulação: safira.policy.accepted-certificate-policies[*].issuer-sha256 "
                    + "(SAFIRA_SIMULACAO_ISSUER_SHA256) é obrigatório — informe o SHA-256 da AC simulada emissora.");
        }
    }

    /**
     * Com {@code safira.simulacao.crls}, a revogação vem só das LCRs locais; sem elas, vale a fábrica
     * padrão de {@link SafiraStepsAutoConfiguration}, presa ao {@link DestinationGuard} sem rede.
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

    /**
     * PKI gerada na partida: revogação (OCSP e LCR) pelas fontes em memória do testkit.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnBean(Resultado.class)
    static class PkiEmMemoriaConfiguration {

        @Bean
        @ConditionalOnMissingBean
        CertificateVerifierFactory simulacaoRevogacaoEmMemoria(Resultado pki) {
            return CertificateVerifierFactory.offline(pki.pki().fonteOcsp(), pki.pki().fonteLcr());
        }

    }
}
