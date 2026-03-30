package br.gov.go.saude.fhir.safira.engine.domain.verification;

import br.gov.go.saude.fhir.safira.engine.domain.Step;

@FunctionalInterface
public interface VerificationStep extends Step<VerificationContext> {}
