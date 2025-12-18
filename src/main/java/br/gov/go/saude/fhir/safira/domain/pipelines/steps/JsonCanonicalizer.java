package br.gov.go.saude.fhir.safira.domain.pipelines.steps;

import br.gov.go.saude.fhir.safira.domain.pipelines.SigningContext;
import br.gov.go.saude.fhir.safira.domain.pipelines.SigningStep;
import br.gov.go.saude.fhir.safira.domain.pipelines.StepId;
import org.springframework.stereotype.Component;

@Component
@StepId("json-canonicalizer")
public class JsonCanonicalizer implements SigningStep {

    @Override
    public void execute(SigningContext context) {
        // Implementação da canonização JSON
    }
}
