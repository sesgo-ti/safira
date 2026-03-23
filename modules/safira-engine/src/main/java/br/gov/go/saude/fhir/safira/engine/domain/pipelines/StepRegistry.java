package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.StepContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Engine's internal registry for Steps and Pipelines.
 * Framework-agnostic. The API or Consumer registers the steps and definitions here.
 */
public class StepRegistry {
private final Map<String, Step<?>> stepIndex = new HashMap<>();
    private final Map<PipelineKey, List<Step<?>>> pipelines = new HashMap<>();

    public void registerStep(String stepId, Step<?> step) {
        if (stepId == null || stepId.isBlank()) {
            throw new IllegalArgumentException("StepId cannot be empty");
        }
        if (stepIndex.putIfAbsent(stepId, step) != null) {
            throw new IllegalStateException("Duplicate StepId: " + stepId);
        }
    }

    public void registerPipeline(PipelineDefinition def) {
        List<Step<?>> steps = new java.util.ArrayList<>();
        for (String id : def.stepIds()) {
            Step<?> step = stepIndex.get(id);
            if (step == null) {
                throw new IllegalStateException("Pipeline " + def.pipelineKey() + " references missing step: " + id);
            }
            steps.add(step);
        }

        if (pipelines.putIfAbsent(def.pipelineKey(), java.util.Collections.unmodifiableList(steps)) != null) {
            throw new IllegalStateException("Duplicate Pipeline for " + def.pipelineKey());
        }
    }

    /**
     * Resolves the configured steps for a given policy version and operation type.
     */
    @SuppressWarnings("unchecked")
    public <C extends StepContext> List<Step<C>> getSteps(String politicsVersion, OperationType operation) {
        List<Step<?>> pipeline = pipelines.get(new PipelineKey(politicsVersion, operation));
        if (pipeline == null) {
             return List.of();
        }
        return pipeline.stream()
                .map(s -> (Step<C>) s)
                .toList();
    }
}
