package br.gov.go.saude.fhir.safira.engine.config;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Import;

@AutoConfiguration
@Import(PipelineConfig.class)
@EnableConfigurationProperties({
        SafiraConfigProperties.class,
        SafiraOperationalConfigProperties.class
})
public class SafiraEngineAutoConfiguration {
}

