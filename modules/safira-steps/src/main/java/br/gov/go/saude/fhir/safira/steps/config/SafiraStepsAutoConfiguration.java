/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.config;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties.VerificationProps;
import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineKey;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.RequiredSteps;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.adapter.DestinationGuard;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSourceFactory;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.signing.CertificatePolicyStep;
import br.gov.go.saude.fhir.safira.steps.signing.ContextValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.FhirSignatureStep;
import br.gov.go.saude.fhir.safira.steps.signing.FramedContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.PkixChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesAssembleStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesDataToSignStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesExtensionStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.TsaTokenVerificationStep;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ContentIntegrityStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.DssValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.JwsStructureStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.SignatureBindingStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.SignerCertificateStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.TimestampValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ValidationOutcomeStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ValidationRequestContextStep;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Registra os steps da política de assinatura 0.2.0 — única versão implementada. A composição
 * das pipelines fica no YAML ({@code safira.pipelines}). A porta {@link FonteDeConfianca} e o
 * {@link DestinationGuard} são fornecidos pela aplicação; sem eles o contexto não sobe (falha fechada).
 */
@AutoConfiguration
@EnableConfigurationProperties(SafiraPolicyProperties.class)
public class SafiraStepsAutoConfiguration {

    /** Fonte de tempo controlada pelo serviço (política C20/C22); sobrescrevível em testes. */
    @Bean
    @ConditionalOnMissingBean
    public Clock safiraClock() {
        return Clock.systemUTC();
    }

    /**
     * Fontes online do DSS (OCSP, CRL) com os timeouts de {@code safira.operational.verification}
     * e destinos filtrados pelo {@link DestinationGuard} da aplicação, obrigatório (sem ele o
     * contexto não sobe); sobrescrevível em testes por {@link CertificateVerifierFactory#offline}.
     */
    @Bean
    @ConditionalOnMissingBean
    public CertificateVerifierFactory safiraCertificateVerifierFactory(SafiraOperationalConfigProperties operational,
                                                                       DestinationGuard destinationGuard) {
        VerificationProps verification = operational.verification();
        return CertificateVerifierFactory.online(verification.ocspTimeout(), verification.crlTimeout(), destinationGuard);
    }

    /** Fonte de carimbo do tempo do JAdES-B-T: TSA online; o simulador a troca por uma em memória. */
    @Bean
    @ConditionalOnMissingBean
    public TspSourceFactory safiraTspSourceFactory() {
        return TspSourceFactory.online();
    }

    /** Verificadores do DSS por operação, com fontes reaproveitadas por geração do acervo. */
    @Bean
    @ConditionalOnMissingBean
    public VerificadoresDss safiraVerificadoresDss(FonteDeConfianca fonteDeConfianca,
                                                   CertificateVerifierFactory factory) {
        return new VerificadoresDss(fonteDeConfianca, factory);
    }

    /** Steps obrigatórios do pipeline SIGNING da política 0.2.0, conferidos na partida pelo {@code PipelineConfig}. */
    @Bean
    public RequiredSteps safiraRequiredSigningSteps() {
        return new RequiredSteps(new PipelineKey(Policy020.POLICY_URI, OperationType.SIGNING), Policy020.REQUIRED_SIGNING_STEPS);
    }

    /** Steps obrigatórios do pipeline VALIDATION da política 0.2.0 (sem {@code dss-validation} a partida falha). */
    @Bean
    public RequiredSteps safiraRequiredValidationSteps() {
        return new RequiredSteps(new PipelineKey(Policy020.POLICY_URI, OperationType.VALIDATION),
                Policy020.REQUIRED_VALIDATION_STEPS);
    }

    @Bean
    public List<Step<?>> safiraAllSteps(FonteDeConfianca fonteDeConfianca,
                                        VerificadoresDss verificadores,
                                        SafiraPolicyProperties policyProperties,
                                        TspSourceFactory tspSources,
                                        Clock clock) {
        List<Step<?>> steps = new ArrayList<>();

        // Assinatura — política 0.2.0 (JAdES-B-B/B-T via EU DSS)
        steps.add(new ContextValidationStep(policyProperties, clock));
        steps.add(new PayloadValidationStep());
        steps.add(new PkixChainValidationStep(verificadores, policyProperties));
        steps.add(new CertificatePolicyStep(policyProperties));
        steps.add(new FramedContentDigestStep());
        steps.add(new JadesDataToSignStep());
        steps.add(new CryptoSigningStep());
        steps.add(new JadesAssembleStep());
        steps.add(new JadesExtensionStep(new JadesExtensionService(), policyProperties, tspSources));
        steps.add(new TsaTokenVerificationStep(verificadores, policyProperties));
        steps.add(new FhirSignatureStep());

        // Validação — política 0.2.0 (EU DSS decide cadeia, revogação e carimbo sobre o acervo ICP-Brasil)
        steps.add(new ValidationRequestContextStep(policyProperties, fonteDeConfianca, clock));
        steps.add(new SignatureBindingStep());
        steps.add(new JwsStructureStep());
        steps.add(new ContentIntegrityStep());
        steps.add(new SignerCertificateStep(policyProperties, verificadores));
        steps.add(new DssValidationStep(verificadores, policyProperties));
        steps.add(new TimestampValidationStep(policyProperties));
        steps.add(new ValidationOutcomeStep());

        return steps;
    }
}
