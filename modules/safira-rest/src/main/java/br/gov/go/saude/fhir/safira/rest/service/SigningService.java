package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import br.gov.go.saude.fhir.safira.rest.mapper.SigningInputMapper;
import org.springframework.stereotype.Service;

@Service
public class SigningService {
    private final PipelineExecutor pipelineExecutor;
    private final SigningInputMapper inputMapper;

    public SigningService(PipelineExecutor pipelineExecutor, SigningInputMapper inputMapper) {
        this.pipelineExecutor = pipelineExecutor;
        this.inputMapper = inputMapper;
    }

    public PipelineResult<?> sign(SigningInput input) {
        SigningContext context = inputMapper.toContext(input);
        
        return pipelineExecutor.sign(input.policyIdentifierUri(), context);
    }
}
