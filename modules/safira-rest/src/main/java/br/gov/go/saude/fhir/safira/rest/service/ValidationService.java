package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.rest.dto.ValidationInput;
import br.gov.go.saude.fhir.safira.rest.mapper.ValidationInputMapper;
import org.springframework.stereotype.Service;

@Service
public class ValidationService {
    private final PipelineExecutor pipelineExecutor;
    private final ValidationInputMapper inputMapper;

    public ValidationService(PipelineExecutor pipelineExecutor, ValidationInputMapper inputMapper) {
        this.pipelineExecutor = pipelineExecutor;
        this.inputMapper = inputMapper;
    }

    public PipelineResult<OperationOutcome> validate(ValidationInput input) {
        ValidationContext context = inputMapper.toContext(input);

        return pipelineExecutor.validate(input.policyIdentifierUri(), context);
    }
}
