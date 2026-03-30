package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.StepContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.engine.domain.verification.VerificationStep;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;
import java.util.Collections;

/**
 * Engine's internal registry for Steps and Pipelines.
 * Framework-agnostic. The API or Consumer registers the steps and definitions here.
 */
public class StepRegistry {
    private static final Logger log = LoggerFactory.getLogger(StepRegistry.class);

    private final Map<String, Step<?>> stepIndex = new HashMap<>();
    private final Map<PipelineKey, List<Step<?>>> pipelines = new HashMap<>();

    public StepRegistry(List<Step<?>> availableSteps, List<PipelineDefinition> definitions) {
        if (availableSteps != null) {
            for (Step<?> step : availableSteps) {
                StepId stepIdAnnotation = step.getClass().getAnnotation(StepId.class);
                if (stepIdAnnotation == null || stepIdAnnotation.value() == null || stepIdAnnotation.value().isBlank()) {
                    throw new IllegalStateException("Step class " + step.getClass() + " is missing a valid @StepId annotation");
                }
                registerStep(stepIdAnnotation.value(), step);
                log.info("Loaded Step - id: '{}',  class: {}", stepIdAnnotation.value(), step.getClass().getSimpleName());
            }
        }

        if (definitions != null) {
            for (PipelineDefinition def : definitions) {
                registerPipeline(def);
                log.info("Loaded Pipeline [{} | {}] -> {}",
                        def.pipelineKey().politicsVersion(),
                        def.pipelineKey().operation(),
                        def.stepIds());
            }
        }
    }

    private void registerStep(String stepId, Step<?> step) {
        if (stepId == null || stepId.isBlank()) {
            throw new IllegalArgumentException("StepId cannot be empty");
        }
        if (stepIndex.putIfAbsent(stepId, step) != null) {
            throw new IllegalStateException("Duplicate StepId: " + stepId);
        }
    }

    private void registerPipeline(PipelineDefinition def) {
        List<Step<?>> steps = new ArrayList<>();
        for (String id : def.stepIds()) {
            Step<?> step = stepIndex.get(id);
            if (step == null) {
                throw new IllegalStateException("Pipeline " + def.pipelineKey() + " references missing step: " + id);
            }

            if (!(step instanceof VerificationStep || step instanceof SigningStep)) {
                throw new IllegalStateException("Step '" + id + "' is neither a VerificationStep nor a SigningStep.");
            }

            if (def.pipelineKey().operation() == OperationType.SIGNING && !(step instanceof SigningStep)) {
                throw new IllegalStateException("Pipeline " + def.pipelineKey() + " is for SIGNING but references a non-signing step: " + id);
            }

            if (def.pipelineKey().operation() == OperationType.VERIFICATION && !(step instanceof VerificationStep)) {
                throw new IllegalStateException("Pipeline " + def.pipelineKey() + " is for VERIFICATION but references a non-verification step: " + id);
            }

            steps.add(step);
        }

        if (pipelines.putIfAbsent(def.pipelineKey(), Collections.unmodifiableList(steps)) != null) {
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
            throw new IllegalArgumentException(
                "No pipeline configured for version: '" + politicsVersion + "' and operation: " + operation
            );
        }
        return pipeline.stream()
                .map(s -> (Step<C>) s)
                .toList();
    }
}
