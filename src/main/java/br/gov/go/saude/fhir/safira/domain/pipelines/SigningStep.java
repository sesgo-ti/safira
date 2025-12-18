package br.gov.go.saude.fhir.safira.domain.pipelines;

public interface SigningStep {
    void execute(SigningContext context);
}
