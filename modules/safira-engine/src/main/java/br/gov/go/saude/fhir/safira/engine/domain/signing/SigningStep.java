package br.gov.go.saude.fhir.safira.engine.domain.signing;

import br.gov.go.saude.fhir.safira.engine.domain.Step;

@FunctionalInterface
public interface SigningStep extends Step<SigningContext> {}
