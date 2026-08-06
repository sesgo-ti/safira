/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepRegistry;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;

import java.util.List;
import java.util.function.Function;

/**
 * Executa pipelines sequencialmente a partir do {@link StepRegistry},
 * curto-circuitando na primeira falha ou exceção técnica.
 */
public class PipelineExecutor {
    private final StepRegistry stepRegistry;

    public PipelineExecutor(StepRegistry stepRegistry) {
        this.stepRegistry = stepRegistry;
    }

    /**
     * Executa o pipeline para a versão de política e operação indicadas.
     *
     * @param politicsVersion versão da política (URI do pipeline)
     * @param operation       tipo de operação (SIGNING, VALIDATION)
     * @param initialContext  contexto inicial fornecido pelo chamador
     * @param resultExtractor extrator do payload final a partir do contexto
     * @return {@link PipelineResult.Success} com o payload ou {@link PipelineResult.Failure} com OperationOutcome
     */
    public <C extends StepContext, T> PipelineResult<T> execute(String politicsVersion, OperationType operation, C initialContext, Function<C, T> resultExtractor) {
        List<Step<C>> steps;
        try {
            steps = stepRegistry.getSteps(politicsVersion, operation);
        } catch (IllegalArgumentException ex) {
            return new PipelineResult.Failure<>(
                    OperationOutcome.createSignatureError("fatal", "processing",
                            SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED.getCode(),
                            SignatureExceptionCode.POLICY_VERSION_UNSUPPORTED.getDisplay(),
                            ex.getMessage())
            );
        }

        C currentContext = initialContext;
        StepResult.Success<C> lastSuccessResult = null;
        
        for (Step<C> step : steps) {
            try {
                StepResult<C> result = step.execute(currentContext);

                switch (result) {
                    case StepResult.Failure<C> failure -> {
                        SignatureExceptionCode ec = failure.code();
                        String severity = ec.getSeverity() != null ? ec.getSeverity() : "error";
                        return new PipelineResult.Failure<>(
                                OperationOutcome.createSignatureError(severity, "processing", ec.getCode(), ec.getDisplay(), failure.diagnostics())
                        );
                    }
                    case StepResult.Success<C> success -> {
                        currentContext = success.context();
                        lastSuccessResult = success;
                    }
                }
            } catch (StepException ex) {
                SignatureExceptionCode ec = ex.getCode();
                String severity = ec.getSeverity() != null ? ec.getSeverity() : "fatal";
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError(severity, "exception", ec.getCode(), ec.getDisplay(), ex.getDiagnostics())
            );
            } catch (Exception ex) {
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError("fatal", "exception", "INTERNAL_ERROR", "Ocorreu um erro interno inesperado: " + ex.getMessage(), ex.getMessage())
                );
            }
        }

        if (lastSuccessResult != null) {
            T payload = resultExtractor.apply(lastSuccessResult.context());
            if (payload == null) {
                return new PipelineResult.Failure<>(
                        OperationOutcome.createSignatureError("fatal", "processing", "INTERNAL_ERROR", "O pipeline finalizou com sucesso, mas nenhum resultado foi produzido.", null)
                );
            }
            return new PipelineResult.Success<>(payload);
        }

        return new PipelineResult.Failure<>(
                OperationOutcome.createSignatureError("fatal", "processing", "INTERNAL_ERROR", "O pipeline finalizou sem concluir nenhum passo com sucesso.", null)
        );
    }

    /** Atalho para executar o pipeline {@code SIGNING}. */
    public PipelineResult<?> sign(String politicsVersion, SigningContext context) {
        return execute(politicsVersion, OperationType.SIGNING, context, SigningContext::getSignature);
    }

    /** Atalho para executar o pipeline {@code VALIDATION}. */
    public PipelineResult<OperationOutcome> validate(String politicsVersion, ValidationContext context) {
        return execute(politicsVersion, OperationType.VALIDATION, context, ValidationContext::getOperationOutcome);
    }
}
