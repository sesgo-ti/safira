package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;

/**
 * Result abstraction for any Pipeline execution (Signature, Verification, etc).
 * Separates the successful delivery of a specific payload (T) from structural failures mapped to OperationOutcome.
 */
public sealed interface PipelineResult<T> permits PipelineResult.Success, PipelineResult.Failure {

    /**
     * @return true if the pipeline was successfully completed.
     */
    boolean isSuccess();

    /**
     * @return true if the pipeline was completely failed.
     */
    default boolean isFailure() {
        return !isSuccess();
    }

    /**
     * @return the result object of type T on success, or null otherwise.
     */
    T getValue();

    /**
     * @return the error details as an OperationOutcome on failure, or null otherwise.
     */
    OperationOutcome getExceptionDetails();

    /**
     * Represents a fully successful pipeline process yielding a valid instance of T.
     */
    record Success<T>(T value) implements PipelineResult<T> {
        @Override public boolean isSuccess() { return true; }
        @Override public T getValue() { return value; }
        @Override public OperationOutcome getExceptionDetails() { return null; }
    }

    /**
     * Represents a failure in the pipeline process yielding a standardized FHIR OperationOutcome exception representation.
     */
    record Failure<T>(OperationOutcome exceptionDetails) implements PipelineResult<T> {
        @Override public boolean isSuccess() { return false; }
        @Override public T getValue() { return null; }
        @Override public OperationOutcome getExceptionDetails() { return exceptionDetails; }
    }
}
