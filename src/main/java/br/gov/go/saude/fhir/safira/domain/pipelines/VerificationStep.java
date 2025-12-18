package br.gov.go.saude.fhir.safira.domain.pipelines;

public interface VerificationStep {
    void execute(VerificationContext context);
}
