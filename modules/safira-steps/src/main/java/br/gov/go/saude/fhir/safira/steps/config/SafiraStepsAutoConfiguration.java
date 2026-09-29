/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.config;

import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
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
import br.gov.go.saude.fhir.safira.steps.validation.jades.ContentIntegrityStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.CurrentChainStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.DssValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.JwsStructureStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.SignatureBindingStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.SignerCertificateStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.TimestampValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ValidationOutcomeStep;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ValidationRequestContextStep;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;

/**
 * Registra os steps da política de assinatura 0.2.0 — única versão implementada. A composição
 * das pipelines fica no YAML ({@code safira.pipelines}).
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

    @Bean
    public List<Step<?>> safiraAllSteps(PkixCertificateValidator pkixCertificateValidator,
                                        RevocationService revocationService,
                                        TrustMaterialSource trustMaterialSource,
                                        SafiraPolicyProperties policyProperties,
                                        Clock clock) {
        List<Step<?>> steps = new ArrayList<>();

        // Assinatura — política 0.2.0 (JAdES-B-B/B-T via EU DSS)
        steps.add(new ContextValidationStep(policyProperties, clock));
        steps.add(new PayloadValidationStep());
        steps.add(new PkixChainValidationStep(pkixCertificateValidator));
        steps.add(new CertificatePolicyStep(policyProperties));
        steps.add(new FramedContentDigestStep());
        steps.add(new JadesDataToSignStep());
        steps.add(new CryptoSigningStep());
        steps.add(new JadesAssembleStep());
        steps.add(new JadesExtensionStep(new JadesExtensionService(), policyProperties));
        steps.add(new TsaTokenVerificationStep(pkixCertificateValidator, policyProperties));
        steps.add(new FhirSignatureStep());

        // Validação — política 0.2.0 (EU DSS com âncoras e revogação da icpbrasil-truststore)
        steps.add(new ValidationRequestContextStep(policyProperties, trustMaterialSource, clock));
        steps.add(new SignatureBindingStep());
        steps.add(new JwsStructureStep());
        steps.add(new ContentIntegrityStep());
        steps.add(new SignerCertificateStep(policyProperties, trustMaterialSource));
        steps.add(new CurrentChainStep(pkixCertificateValidator));
        steps.add(new DssValidationStep(revocationService, trustMaterialSource, policyProperties));
        steps.add(new TimestampValidationStep(policyProperties));
        steps.add(new ValidationOutcomeStep());

        return steps;
    }
}
