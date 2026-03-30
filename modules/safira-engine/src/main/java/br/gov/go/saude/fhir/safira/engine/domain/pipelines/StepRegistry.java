package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.StepContext;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Engine's internal registry for Pipelines.
 * Framework-agnostic. Receives already-resolved pipelines (PipelineKey → ordered steps).
 */
public class StepRegistry {
    private static final Logger log = LoggerFactory.getLogger(StepRegistry.class);

    private final Map<PipelineKey, List<Step<?>>> pipelines = new HashMap<>();

    public StepRegistry(Map<PipelineKey, List<Step<?>>> resolvedPipelines) {
        if (resolvedPipelines != null) {
            for (Map.Entry<PipelineKey, List<Step<?>>> entry : resolvedPipelines.entrySet()) {
                PipelineKey key = entry.getKey();
                List<Step<?>> steps = entry.getValue();

                if (pipelines.putIfAbsent(key, Collections.unmodifiableList(steps)) != null) {
                    throw new IllegalStateException("Duplicate Pipeline for " + key);
                }

                log.info("Loaded Pipeline [{} | {}] -> {} step(s)",
                        key.politicsVersion(), key.operation(), steps.size());
            }
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
