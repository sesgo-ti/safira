package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import java.util.List;

public record PipelineDefinition(
        PipelineKey pipelineKey,
        List<String> stepIds
) {}
