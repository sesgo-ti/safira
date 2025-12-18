package br.gov.go.saude.fhir.safira.domain.pipelines;

import br.gov.go.saude.fhir.safira.domain.OperationType;

public record PipelineKey(
        String politicsVersion,
        OperationType operation
) {}