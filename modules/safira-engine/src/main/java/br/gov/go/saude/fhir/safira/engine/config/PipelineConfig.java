package br.gov.go.saude.fhir.safira.engine.config;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineKey;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepRegistry;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

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

        return new StepRegistry(availableSteps, definitions);
    }

    @Bean
    public PipelineExecutor pipelineExecutor(StepRegistry stepRegistry) {
        return new PipelineExecutor(stepRegistry);
    }
}
