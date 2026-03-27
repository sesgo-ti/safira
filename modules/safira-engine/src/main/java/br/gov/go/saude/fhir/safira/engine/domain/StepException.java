/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import lombok.Getter;

/**
 * Exceção lançada quando ocorre um erro técnico durante a execução de um
 * {@link Step}.
 *
 * <p>
 * Diferente de um {@link ResultStep.Fail}, que representa uma falha de
 * validação ou resultado esperado de uma regra de negócio,
 * esta exceção indica que o passo não pôde ser concluído devido a um erro de
 * sistema, infraestrutura ou configuração (ex: falha de IO, serviço
 * indisponível, erro de criptografia).
 * </p>
 */
@Getter
public class StepException extends RuntimeException {

    public static final String DEFAULT_MSG = "STEP_EXECUTION_ERROR";
    private final String code;
    private final String description;

    public StepException(String code, String description, Throwable cause) {
        super(code + ": " + description, cause);
        this.code = code;
        this.description = description;
    }

    public StepException(String code, String description) {
        super(code + ": " + description);
        this.code = code;
        this.description = description;
    }

    /**
     * Cria uma exceção com um código e uma causa.
     *
     * @param code  código do erro que causou a exceção
     * @param cause causa raiz
     */
    public StepException(String code, Throwable cause) {
        this(code, DEFAULT_MSG, cause);
    }

    /**
     * Cria uma exceção apenas com um código.
     *
     * @param code código do erro que causou a exceção
     */
    public StepException(String code) {
        this(code, DEFAULT_MSG);
    }
}
