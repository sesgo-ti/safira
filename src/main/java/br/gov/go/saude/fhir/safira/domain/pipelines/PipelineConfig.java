package br.gov.go.saude.fhir.safira.domain.pipelines;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.stream.Stream;

import static br.gov.go.saude.fhir.safira.domain.OperationType.*;
import static br.gov.go.saude.fhir.safira.domain.PoliticsVersion.*;

@Configuration
public class PipelineConfig {

    @Bean
    public List<PipelineDefinition> pipelines() {
        List<PipelineDefinition> signingPipelines = signingPipelines();
        List<PipelineDefinition> verificationPipelines = verificationPipelines();
        return Stream.concat(signingPipelines.stream(), verificationPipelines.stream())
                     .toList();
    }

    public List<PipelineDefinition> signingPipelines() {
        return List.of(
                new PipelineDefinition(
                        new PipelineKey(BR_GO_SES_SEGURANCA_0_1_0, SIGNING),
                        List.of("json-canonicalizer")
                )
        );
    }

    public List<PipelineDefinition> verificationPipelines() {
        return List.of(
                new PipelineDefinition(
                        new PipelineKey(BR_GO_SES_SEGURANCA_0_1_0, VERIFICATION),
                        List.of("json-canonicalization-validator")
                )
        );
    }
}
