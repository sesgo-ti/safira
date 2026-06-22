package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;

/**
 * Resultado de execução do pipeline: {@link Success} com payload tipado
 * ou {@link Failure} com {@link OperationOutcome} FHIR.
 *
 * @param <T> tipo do payload entregue em caso de sucesso
 */
public sealed interface PipelineResult<T> permits PipelineResult.Success, PipelineResult.Failure {

    boolean isSuccess();

    default boolean isFailure() {
        return !isSuccess();
    }

    T getValue();

    OperationOutcome getExceptionDetails();

    record Success<T>(T value) implements PipelineResult<T> {
        @Override public boolean isSuccess() { return true; }
        @Override public T getValue() { return value; }
        @Override public OperationOutcome getExceptionDetails() { return null; }
    }

    record Failure<T>(OperationOutcome exceptionDetails) implements PipelineResult<T> {
        @Override public boolean isSuccess() { return false; }
        @Override public T getValue() { return null; }
        @Override public OperationOutcome getExceptionDetails() { return exceptionDetails; }
    }
}
