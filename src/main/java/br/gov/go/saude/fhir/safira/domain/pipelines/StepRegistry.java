package br.gov.go.saude.fhir.safira.domain.pipelines;

import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static br.gov.go.saude.fhir.safira.domain.OperationType.SIGNING;
import static br.gov.go.saude.fhir.safira.domain.OperationType.VERIFICATION;

@Component
public class StepRegistry {
    private final Map<String, Object> stepIndex;
    private final Map<PipelineKey, List<Object>> pipelines;

    public StepRegistry(
            List<VerificationStep> verificationSteps,
            List<SigningStep> signingSteps,
            List<PipelineDefinition> definitions) {

        this.stepIndex = indexSteps(verificationSteps, signingSteps);
        this.pipelines = buildPipelines(definitions);
    }

    public List<VerificationStep> verification(String politicsVersion) {
        return pipelines.get(new PipelineKey(politicsVersion, VERIFICATION))
                .stream()
                .map(VerificationStep.class::cast)
                .toList();
    }

    public List<SigningStep> signing(String politicsVersion) {
        return pipelines.get(new PipelineKey(politicsVersion, SIGNING))
                .stream()
                .map(SigningStep.class::cast)
                .toList();
    }

    private Map<PipelineKey, List<Object>> buildPipelines(
            List<PipelineDefinition> definitions) {

        Map<PipelineKey, List<Object>> result = new HashMap<>();

        for (PipelineDefinition def : definitions) {
            PipelineKey key = new PipelineKey(
                    def.pipelineKey().politicsVersion(), def.pipelineKey().operation()
            );

            List<Object> steps = def.stepIds().stream()
                    .map(id -> {
                        Object step = stepIndex.get(id);
                        if (step == null) {
                            throw new IllegalStateException(
                                    "Pipeline " + key + " referencia step inexistente: " + id
                            );
                        }
                        return step;
                    })
                    .toList();

            if (result.putIfAbsent(key, steps) != null) {
                throw new IllegalStateException(
                        "Pipeline duplicada para " + key
                );
            }
        }

        return Map.copyOf(result);
    }

    private Map<String, Object> indexSteps(
            List<VerificationStep> verification,
            List<SigningStep> signing) {

        Map<String, Object> index = new HashMap<>();

        Stream.concat(verification.stream(), signing.stream())
                .forEach(step -> {
                    StepId id = step.getClass().getAnnotation(StepId.class);

                    if (id == null) {
                        throw new IllegalStateException(
                                "Step sem @StepId: " + step.getClass()
                        );
                    }

                    if (!StringUtils.hasText(id.value())) {
                        throw new IllegalStateException(
                                "StepId vazio na classe: " + step.getClass()
                        );
                    }

                    if (index.putIfAbsent(id.value(), step) != null) {
                        throw new IllegalStateException(
                                "StepId duplicado: " + id.value()
                        );
                    }
                });

        return Map.copyOf(index);
    }
}