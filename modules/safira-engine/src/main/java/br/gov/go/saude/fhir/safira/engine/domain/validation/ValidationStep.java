package br.gov.go.saude.fhir.safira.engine.domain.validation;

import br.gov.go.saude.fhir.safira.engine.domain.Step;

@FunctionalInterface
public interface ValidationStep extends Step<ValidationContext> {}
