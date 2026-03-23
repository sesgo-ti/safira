package br.gov.go.saude.fhir.safira.engine.domain;

import java.util.List;

/**
 * The standard sequence executor. Once configured with an ordered list of Steps, 
 * it runs them sequentially holding the current Context flow.
 */
public class PipelineExecutor<C extends StepContext> {
    private final List<Step<C>> steps;

    public PipelineExecutor(List<Step<C>> steps) {
        this.steps = steps;
    }

    /**
     * Executes the sequence of steps.
     * 
     * @param initialContext current context injected by the client caller
     * @return ResultStep containing the enriched context on success or the exact failure outcome on error
     */
    public ResultStep<C> execute(C initialContext) {
        if (steps == null || steps.isEmpty()) {
            return new ResultStep.Ok<>(initialContext);
        }

        C currentContext = initialContext;
        for (Step<C> step : steps) {
            try {
                ResultStep<C> result = step.execute(currentContext);
                
                if (result instanceof ResultStep.Fail<C> fail) {
                    return fail; // Pipeline stops on first failure
                }
                
                if (result instanceof ResultStep.Ok<C> ok) {
                    currentContext = ok.context(); // Pipeline carries the enriched context forward
                }
            } catch (StepException ex) {
                return new ResultStep.Fail<>(ex.getCode(), ex.getDescription());
            } catch (Exception ex) {
                return new ResultStep.Fail<>("INTERNAL_ERROR", "Pipeline failed at step " + step.getName() + ": " + ex.getMessage());
            }
        }
        
        return new ResultStep.Ok<>(currentContext);
    }
}
