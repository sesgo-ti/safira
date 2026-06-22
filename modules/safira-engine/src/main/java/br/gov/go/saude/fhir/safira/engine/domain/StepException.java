/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import lombok.Getter;

/**
 * Indica erro técnico irrecuperável durante a execução de um {@link Step} —
 * distinto de {@link StepResult.Failure}, que representa falha de regra de negócio esperada.
 *
 * <p>Exemplos: falha de IO, serviço indisponível, erro criptográfico de sistema.
 */
@Getter
public class StepException extends RuntimeException {

    public static final String DEFAULT_MSG = "STEP_EXECUTION_ERROR";
    private final SignatureExceptionCode code;
    private final String diagnostics;

    public StepException(SignatureExceptionCode code, String diagnostics, Throwable cause) {
        super(diagnostics, cause);
        this.code = code;
        this.diagnostics = diagnostics;
    }

    public StepException(SignatureExceptionCode code, String diagnostics) {
        super(diagnostics);
        this.code = code;
        this.diagnostics = diagnostics;
    }

    public StepException(SignatureExceptionCode code, Throwable cause) {
        this(code, DEFAULT_MSG, cause);
    }

    public StepException(SignatureExceptionCode code) {
        this(code, DEFAULT_MSG);
    }
}
