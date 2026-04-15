package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepRegistry;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;

import java.util.List;
import java.util.function.Function;

/**
 * The standard sequence executor for pipelines.
 * Resolves the appropriate steps from the registry and executes them sequentially.
 */
public class PipelineExecutor {
    private final StepRegistry stepRegistry;

    public PipelineExecutor(StepRegistry stepRegistry) {
        this.stepRegistry = stepRegistry;
    }

    /**
     * Executes the pipeline sequence for a specific configuration.
     *
     * @param politicsVersion the version of the pipeline policy to load
     * @param operation the operation type (SIGNING, VALIDATION, etc.)
     * @param initialContext current context injected by the client caller
     * @param resultExtractor function to extract the final payload T from the context
     * @return PipelineResult containing the extracted payload on success or the failure outcome
     */
    public <C extends StepContext, T> PipelineResult<T> execute(String politicsVersion, OperationType operation, C initialContext, Function<C, T> resultExtractor) {
        List<Step<C>> steps;
        try {
            steps = stepRegistry.getSteps(politicsVersion, operation);
        } catch (IllegalArgumentException ex) {
            return new PipelineResult.Failure<>(
                    OperationOutcome.createSignatureError("fatal", "processing",
                            SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED.getCode(),
                            SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED.getDisplay(),
                            ex.getMessage())
            );
        }

        C currentContext = initialContext;
        StepResult.Success<C> lastSuccessResult = null;
        
        for (Step<C> step : steps) {
            try {
                StepResult<C> result = step.execute(currentContext);

                switch (result) {
                    case StepResult.Failure<C> failure -> {
                        SignatureExceptionCode ec = failure.code();
                        String severity = ec.getSeverity() != null ? ec.getSeverity() : "error";
                        return new PipelineResult.Failure<>(
                                OperationOutcome.createSignatureError(severity, "processing", ec.getCode(), ec.getDisplay(), failure.diagnostics())
                        );
                    }
                    case StepResult.Success<C> success -> {
                        currentContext = success.context();
                        lastSuccessResult = success;
                    }
                }
            } catch (StepException ex) {
                SignatureExceptionCode ec = ex.getCode();
                String severity = ec.getSeverity() != null ? ec.getSeverity() : "fatal";
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError(severity, "exception", ec.getCode(), ec.getDisplay(), ex.getDiagnostics())
            );
            } catch (Exception ex) {
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError("fatal", "exception", "INTERNAL_ERROR", "Ocorreu um erro interno inesperado: " + ex.getMessage(), ex.getMessage())
                );
            }
        }

        if (lastSuccessResult != null) {
            T payload = resultExtractor.apply(lastSuccessResult.context());
            if (payload == null) {
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError("fatal", "processing", "INTERNAL_ERROR", "O pipeline finalizou com sucesso, mas nenhum resultado foi produzido.", null)
                );
            }
            return new PipelineResult.Success<>(payload);
        }

        return new PipelineResult.Failure<>(
                OperationOutcome.createSignatureError("fatal", "processing", "INTERNAL_ERROR", "O pipeline finalizou sem concluir nenhum passo com sucesso.", null)
        );
    }

    /**
     * Convenience method for executing the SIGNING pipeline.
     *
     * @param politicsVersion version of the pipeline policy to load
     * @param context current context injected by the client caller
     * @return PipelineResult containing the extracted payload on success or OperationOutcome on failure
     */
    public PipelineResult<?> sign(String politicsVersion, SigningContext context) {
        return execute(politicsVersion, OperationType.SIGNING, context, SigningContext::getSignature);
    }

    /**
     * Convenience method for executing the VALIDATION pipeline.
     *
     * @param politicsVersion version of the pipeline policy to load
     * @param context current validation context injected by the client caller
     * @return PipelineResult containing the final OperationOutcome on success or a failure OperationOutcome on failure
     */
    public PipelineResult<OperationOutcome> validate(String politicsVersion, ValidationContext context) {
        return execute(politicsVersion, OperationType.VALIDATION, context, ValidationContext::getOperationOutcome);
    }
}
