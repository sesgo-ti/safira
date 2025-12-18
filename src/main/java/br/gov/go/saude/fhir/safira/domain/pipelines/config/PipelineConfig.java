package br.gov.go.saude.fhir.safira.domain.pipelines.config;

import br.gov.go.saude.fhir.safira.domain.pipelines.PipelineDefinition;
import br.gov.go.saude.fhir.safira.domain.pipelines.PipelineKey;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class PipelineConfig {

    private final PipelineProperties properties;

    public PipelineConfig(PipelineProperties properties) {
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