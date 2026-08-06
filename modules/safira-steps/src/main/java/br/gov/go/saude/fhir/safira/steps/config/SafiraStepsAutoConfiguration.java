/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.config;

import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.steps.signing.ChainBuildStep;
import br.gov.go.saude.fhir.safira.steps.signing.ChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.ContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.ContextValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.FhirSignatureStep;
import br.gov.go.saude.fhir.safira.steps.signing.JsonCanonicalizationStep;
import br.gov.go.saude.fhir.safira.steps.signing.JwsFinalStep;
import br.gov.go.saude.fhir.safira.steps.signing.JwsPreliminaryStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadPreparationStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.ProtectedHeaderStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningInputStep;
import br.gov.go.saude.fhir.safira.steps.signing.TsaTimestampStep;
import br.gov.go.saude.fhir.safira.steps.validation.JwsExtractionStep;
import br.gov.go.saude.fhir.safira.steps.validation.JwsHeadersValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.LtvRevocationCheckStep;
import br.gov.go.saude.fhir.safira.steps.validation.PayloadIntegrityVerificationStep;
import br.gov.go.saude.fhir.safira.steps.validation.SignatureCryptoVerificationStep;
import br.gov.go.saude.fhir.safira.steps.validation.TimestampPolicyValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.ValidationChainBuildStep;
import br.gov.go.saude.fhir.safira.steps.validation.ValidationChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.ValidationContextValidationStep;
import br.gov.go.saude.fhir.safira.steps.validation.ValidationSuccessStep;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation.RevocationService;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class SafiraStepsAutoConfiguration {

    @Bean
    public List<Step<?>> safiraAllSteps(TrustStoreService trustStoreService,
                                        RevocationService revocationService,
                                        CertificateChainResolver certificateChainResolver,
                                        List<PipelineDefinition> pipelineDefinitions) {
        List<Step<?>> steps = new ArrayList<>();

        // Signing steps
        steps.add(new ContextValidationStep());
        steps.add(new PayloadValidationStep());
        steps.add(new ChainBuildStep(certificateChainResolver));
        steps.add(new ChainValidationStep(trustStoreService, revocationService));
        steps.add(new PayloadPreparationStep());
        steps.add(new JsonCanonicalizationStep());
        steps.add(new ContentDigestStep());
        steps.add(new ProtectedHeaderStep());
        steps.add(new SigningInputStep());
        steps.add(new CryptoSigningStep());
        steps.add(new JwsPreliminaryStep());
        steps.add(new TsaTimestampStep());
        steps.add(new JwsFinalStep());
        steps.add(new FhirSignatureStep());

        // Validation steps
        steps.add(new ValidationContextValidationStep(pipelineDefinitions));
        steps.add(new JwsExtractionStep());
        steps.add(new JwsHeadersValidationStep());
        steps.add(new ValidationChainBuildStep());
        steps.add(new ValidationChainValidationStep(trustStoreService));
        steps.add(new SignatureCryptoVerificationStep());
        steps.add(new LtvRevocationCheckStep());
        steps.add(new TimestampPolicyValidationStep());
        steps.add(new PayloadIntegrityVerificationStep());
        steps.add(new ValidationSuccessStep());

        return steps;
    }
}
