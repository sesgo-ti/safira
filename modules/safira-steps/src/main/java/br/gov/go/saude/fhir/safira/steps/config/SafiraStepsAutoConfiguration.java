package br.gov.go.saude.fhir.safira.steps.config;

import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.steps.signing.ContextValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.JsonCanonicalizationStep;
import br.gov.go.saude.fhir.safira.steps.signing.PayloadValidationStep;

import java.util.List;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.context.annotation.Bean;

@AutoConfiguration
public class SafiraStepsAutoConfiguration {

    @Bean
    public List<Step<?>> safiraSignatureSteps() {
        return List.of(
            new ContextValidationStep(),
            new PayloadValidationStep(),
            new JsonCanonicalizationStep()
        );
    }
}
