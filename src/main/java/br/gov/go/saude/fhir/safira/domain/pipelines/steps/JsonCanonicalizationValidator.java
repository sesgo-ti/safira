package br.gov.go.saude.fhir.safira.domain.pipelines.steps;

import br.gov.go.saude.fhir.safira.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.domain.pipelines.VerificationContext;
import br.gov.go.saude.fhir.safira.domain.pipelines.VerificationStep;
import org.springframework.stereotype.Component;

@Component
@StepId("json-canonicalization-validator")
public class JsonCanonicalizationValidator implements VerificationStep {

    @Override
    public void execute(VerificationContext context) {
        // Implementação da validação se um json está canonicalizado corretamente
    }
}
