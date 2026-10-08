/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.rest.request.RequestParsingException;
import br.gov.go.saude.fhir.safira.rest.request.ValidationRequestParser;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacao;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Orquestra a validação de assinatura: leitura lossless da requisição e execução da pipeline
 * única da política 0.2.0. A política solicitada é verificada pelo step {@code validation-context}.
 */
@Service
public class ValidationService {

    private final PipelineExecutor pipelineExecutor;
    private final SafiraOperationalConfigProperties operationalConfig;
    private final Optional<AvisoSimulacao> avisoSimulacao;

    public ValidationService(PipelineExecutor pipelineExecutor, SafiraOperationalConfigProperties operationalConfig) {
        this(pipelineExecutor, operationalConfig, Optional.empty());
    }

    /**
     * @param avisoSimulacao presente só no modo simulação: o sucesso ganha a issue
     *                       "SIMULAÇÃO — sem validade jurídica ICP-Brasil"
     */
    @Autowired
    public ValidationService(PipelineExecutor pipelineExecutor, SafiraOperationalConfigProperties operationalConfig,
                             Optional<AvisoSimulacao> avisoSimulacao) {
        this.pipelineExecutor = pipelineExecutor;
        this.operationalConfig = operationalConfig;
        this.avisoSimulacao = avisoSimulacao;
    }

    /**
     * @param body corpo JSON cru de {@code POST /validar}
     * @return {@code OperationOutcome} de sucesso ({@code VALIDATION.SUCCESS}) ou de rejeição
     */
    public PipelineResult<OperationOutcome> validate(String body) {
        ValidationContext context;
        try {
            context = ValidationRequestParser.parse(body, operationalConfig);
        } catch (RequestParsingException e) {
            return new PipelineResult.Failure<>(OperationOutcome.createSignatureError(
                    e.getCode().getSeverity() != null ? e.getCode().getSeverity() : "error", "invalid",
                    e.getCode().getCode(), e.getCode().getDisplay(), e.getMessage()));
        }
        PipelineResult<OperationOutcome> result = pipelineExecutor.validate(Policy020.POLICY_URI, context);
        if (result instanceof PipelineResult.Success<OperationOutcome> success && avisoSimulacao.isPresent()) {
            return new PipelineResult.Success<>(avisoSimulacao.get().marcar(success.getValue()));
        }
        return result;
    }
}
