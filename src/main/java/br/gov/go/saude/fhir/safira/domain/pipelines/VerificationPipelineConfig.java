package br.gov.go.saude.fhir.safira.domain.pipelines;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

import static br.gov.go.saude.fhir.safira.domain.PoliticsVersion.*;
import static br.gov.go.saude.fhir.safira.domain.OperationType.*;

@Configuration
public class VerificationPipelineConfig {
    @Bean
    public List<PipelineDefinition> verificationPipelines() {
        return List.of(
                new PipelineDefinition(
                        new PipelineKey(BR_GO_SES_SEGURANCA_0_1_0, VERIFICATION),
                        List.of("json-canonicalization-validator")
                )
        );
    }
}