package br.gov.go.saude.fhir.safira.domain.pipelines;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

import static br.gov.go.saude.fhir.safira.domain.OperationType.SIGNING;
import static br.gov.go.saude.fhir.safira.domain.PoliticsVersion.BR_GO_SES_SEGURANCA_0_1_0;

@Configuration
public class SigningPipelineConfig {
    @Bean
    public List<PipelineDefinition> signingPipelines() {
        return List.of(
                new PipelineDefinition(
                        new PipelineKey(BR_GO_SES_SEGURANCA_0_1_0, SIGNING),     
                        List.of("json-canonicalizer")
                )
        );
    }
}