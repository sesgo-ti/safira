package br.gov.go.saude.fhir.safira.engine.config;

import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.PipelineKey;
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
        return properties.getPipelines().stream()
                .map(entry -> new PipelineDefinition(
                        new PipelineKey(entry.getVersion(), entry.getOperation()),
                        entry.getSteps()
                ))
                .toList();
    }
}
