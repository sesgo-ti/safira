package br.gov.go.saude.fhir.safira.domain.pipelines;

import br.gov.go.saude.fhir.safira.domain.OperationType;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.ArrayList;
import java.util.List;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "safira")
public class PipelineProperties {

    private List<PipelineConfigEntry> pipelines = new ArrayList<>();

    @Getter
    @Setter
    public static class PipelineConfigEntry {
        private String version;
        private OperationType operation;
        private List<String> steps;
    }
}