package br.gov.go.saude.fhir.safira.engine.domain;

/**
 * Represents the result of a {@link Step} execution.
 * Allows safe return of validation failures or success without throwing runtime exceptions.
 */
public sealed interface ResultStep<C extends StepContext> permits ResultStep.Ok, ResultStep.Fail {

    record Ok<C extends StepContext>(C context) implements ResultStep<C> {}

    record Fail<C extends StepContext>(String code, String details) implements ResultStep<C> {}
}
