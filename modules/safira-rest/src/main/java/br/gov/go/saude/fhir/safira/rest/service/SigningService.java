/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.rest.service;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineExecutor;
import br.gov.go.saude.fhir.safira.engine.domain.PipelineResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.rest.request.RequestParsingException;
import br.gov.go.saude.fhir.safira.rest.request.SigningRequestParser;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import org.springframework.stereotype.Service;

/**
 * Orquestra a criação de assinatura: leitura lossless da requisição e execução da pipeline
 * única da política 0.2.0. A política solicitada na requisição é verificada pelo step
 * {@code context-validation}, que devolve os códigos do IG (URI inválida, versão não suportada).
 */
@Service
public class SigningService {

    private final PipelineExecutor pipelineExecutor;
    private final SafiraOperationalConfigProperties operationalConfig;

    public SigningService(PipelineExecutor pipelineExecutor, SafiraOperationalConfigProperties operationalConfig) {
        this.pipelineExecutor = pipelineExecutor;
        this.operationalConfig = operationalConfig;
    }

    /**
     * @param body corpo JSON cru de {@code POST /assinar}
     * @return {@code SigningResult} em caso de sucesso ou {@code OperationOutcome} de falha
     */
    public PipelineResult<?> sign(String body) {
        SigningContext context;
        try {
            context = SigningRequestParser.parse(body, operationalConfig);
        } catch (RequestParsingException e) {
            return new PipelineResult.Failure<>(OperationOutcome.createSignatureError(
                    e.getCode().getSeverity() != null ? e.getCode().getSeverity() : "error", "invalid",
                    e.getCode().getCode(), e.getCode().getDisplay(), e.getMessage()));
        }
        return pipelineExecutor.sign(Policy020.POLICY_URI, context);
    }
}
