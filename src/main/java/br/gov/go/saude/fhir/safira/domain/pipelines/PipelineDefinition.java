package br.gov.go.saude.fhir.safira.domain.pipelines;

import java.util.List;

public record PipelineDefinition(
        PipelineKey pipelineKey,
        List<String> stepIds
) {}

