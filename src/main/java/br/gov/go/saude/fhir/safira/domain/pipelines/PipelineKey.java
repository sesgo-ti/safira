package br.gov.go.saude.fhir.safira.domain.pipelines;

import br.gov.go.saude.fhir.safira.domain.OperationType;
import br.gov.go.saude.fhir.safira.domain.PoliticsVersion;

public record PipelineKey(
        PoliticsVersion version,
        OperationType operation
) {}

