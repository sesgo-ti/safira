package br.gov.go.saude.fhir.safira.steps.config;

import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.steps.signing.ChainBuildStep;
import br.gov.go.saude.fhir.safira.steps.signing.ChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.ContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.ContextValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.JsonCanonicalizationStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadPreparationStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.ProtectedHeaderStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningInputStep;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.CertificateChainResolver;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.TrustStoreService;
import br.gov.go.saude.fhir.truststore.icpbrasil.service.revocation.RevocationService;

import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class SafiraStepsAutoConfiguration {

    @Bean
    public List<Step<?>> safiraSignatureSteps(TrustStoreService trustStoreService,
                                              RevocationService revocationService,
                                              CertificateChainResolver certificateChainResolver) {
        return List.of(
            new ContextValidationStep(),
            new PayloadValidationStep(),
            new ChainBuildStep(certificateChainResolver),
            new ChainValidationStep(trustStoreService, revocationService),
            new PayloadPreparationStep(),
            new JsonCanonicalizationStep(),
            new ContentDigestStep(),
            new ProtectedHeaderStep(),
            new SigningInputStep(),
            new CryptoSigningStep()
        );
    }
}
