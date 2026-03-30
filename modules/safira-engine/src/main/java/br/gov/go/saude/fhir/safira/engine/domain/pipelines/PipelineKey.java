package br.gov.go.saude.fhir.safira.engine.domain.pipelines;

import br.gov.go.saude.fhir.safira.engine.domain.OperationType;

public record PipelineKey(
        String politicsVersion,
        OperationType operation
) {}
