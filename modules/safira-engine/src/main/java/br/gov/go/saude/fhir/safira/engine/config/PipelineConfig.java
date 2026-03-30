package br.gov.go.saude.fhir.safira.engine.config;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineKey;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepRegistry;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.engine.domain.verification.VerificationStep;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

@Configuration
public class PipelineConfig {

    private final SafiraConfigProperties properties;

    public PipelineConfig(SafiraConfigProperties properties) {
        this.properties = properties;
    }

    @Bean
    public List<PipelineDefinition> pipelines() {
        return properties.pipelines().stream()
                .map(entry -> new PipelineDefinition(
                        new PipelineKey(entry.version(), entry.operation()),
                        entry.steps()
                ))
                .toList();
    }

    @Bean
    public StepRegistry stepRegistry(
            List<Step<?>> availableSteps,
            List<PipelineDefinition> definitions) {

        Map<String, Step<?>> stepIndex = indexStepsByAnnotation(availableSteps);
        Map<PipelineKey, List<Step<?>>> resolvedPipelines = resolvePipelines(definitions, stepIndex);

        return new StepRegistry(resolvedPipelines);
    }

    @Bean
    public PipelineExecutor pipelineExecutor(StepRegistry stepRegistry) {
        return new PipelineExecutor(stepRegistry);
    }

    private Map<String, Step<?>> indexStepsByAnnotation(List<Step<?>> steps) {
        Map<String, Step<?>> index = new LinkedHashMap<>();

        if (steps == null) {
            return index;
        }

        for (Step<?> step : steps) {
            StepId annotation = step.getClass().getAnnotation(StepId.class);
            if (annotation == null || annotation.value() == null || annotation.value().isBlank()) {
                throw new IllegalStateException(
                    "Step class " + step.getClass().getName() + " is missing a valid @StepId annotation"
                );
            }

            String id = annotation.value();
            if (index.putIfAbsent(id, step) != null) {
                throw new IllegalStateException("Duplicate StepId: " + id);
            }
        }

        return index;
    }

    private Map<PipelineKey, List<Step<?>>> resolvePipelines(
            List<PipelineDefinition> definitions,
            Map<String, Step<?>> stepIndex) {

        Map<PipelineKey, List<Step<?>>> resolved = new HashMap<>();

        if (definitions == null) {
            return resolved;
        }

        for (PipelineDefinition def : definitions) {
            List<Step<?>> steps = new ArrayList<>();

            for (String id : def.stepIds()) {
                Step<?> step = stepIndex.get(id);
                if (step == null) {
                    throw new IllegalStateException(
                        "Pipeline " + def.pipelineKey() + " references missing step: " + id
                    );
                }

                if (!(step instanceof VerificationStep || step instanceof SigningStep)) {
                    throw new IllegalStateException(
                        "Step '" + id + "' is neither a VerificationStep nor a SigningStep."
                    );
                }

                if (def.pipelineKey().operation() == OperationType.SIGNING && !(step instanceof SigningStep)) {
                    throw new IllegalStateException(
                        "Pipeline " + def.pipelineKey() + " is for SIGNING but references a non-signing step: " + id
                    );
                }

                if (def.pipelineKey().operation() == OperationType.VERIFICATION && !(step instanceof VerificationStep)) {
                    throw new IllegalStateException(
                        "Pipeline " + def.pipelineKey() + " is for VERIFICATION but references a non-verification step: " + id
                    );
                }

                steps.add(step);
            }

            resolved.put(def.pipelineKey(), steps);
        }

        return resolved;
    }
}
