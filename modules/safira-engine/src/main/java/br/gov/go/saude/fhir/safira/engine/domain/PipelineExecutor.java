package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepRegistry;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;

import java.util.List;

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
     * @param operation the operation type (SIGNING, VERIFICATION, etc.)
     * @param initialContext current context injected by the client caller
     * @return ResultStep containing the enriched context on success or the failure outcome
     */
    public <C extends StepContext> ResultStep<C> execute(String politicsVersion, OperationType operation, C initialContext) {
        List<Step<C>> steps = stepRegistry.getSteps(politicsVersion, operation);

        C currentContext = initialContext;
        ResultStep<C> lastResult = null;
        for (Step<C> step : steps) {
            try {
                ResultStep<C> result = step.execute(currentContext);

                switch (result) {
                    case ResultStep.Fail<C> fail -> {
                        return fail; // Pipeline stops on first failure
                    }
                    case ResultStep.Ok<C> ok -> {
                        currentContext = ok.context(); // Pipeline carries the enriched context forward
                        lastResult = ok; // Keep track of the last successful step
                    }
                }
            } catch (StepException ex) {
                throw ex;
            } catch (Exception ex) {
                throw new StepException("INTERNAL_ERROR", "Pipeline failed at step " + step.getName() + ": " + ex.getMessage(), ex);
            }
        }

        return lastResult;
    }

    /**
     * Convenience method for executing the SIGNING pipeline.
     */
    public ResultStep<SigningContext> sign(String politicsVersion, SigningContext context) {
        return execute(politicsVersion, OperationType.SIGNING, context);
    }

    /**
     * Convenience method for executing the VERIFICATION pipeline.
     */
    public <C extends StepContext> ResultStep<C> verify(String politicsVersion, C context) {
        return execute(politicsVersion, OperationType.VERIFICATION, context);
    }
}
