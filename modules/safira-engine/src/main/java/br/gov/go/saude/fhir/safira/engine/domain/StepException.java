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
 * Exceção lançada quando ocorre um erro técnico durante a execução de um
 * {@link Step}.
 *
 * <p>
 * Diferente de um {@link StepResult.Failure}, que representa uma falha de
 * validação ou resultado esperado de uma regra de negócio,
 * esta exceção indica que o passo não pôde ser concluído devido a um erro de
 * sistema, infraestrutura ou configuração (ex: falha de IO, serviço
 * indisponível, erro de criptografia).
 * </p>
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

    /**
     * Cria uma exceção com um código e uma causa.
     *
     * @param code  código do erro que causou a exceção
     * @param cause causa raiz
     */
    public StepException(SignatureExceptionCode code, Throwable cause) {
        this(code, DEFAULT_MSG, cause);
    }

    /**
     * Cria uma exceção apenas com um código.
     *
     * @param code código do erro que causou a exceção
     */
    public StepException(SignatureExceptionCode code) {
        this(code, DEFAULT_MSG);
    }
}
