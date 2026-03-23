/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;

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
 *
 * @since 1.0.0
 */
public class StepException extends SafiraException {

    public static final String DEFAULT_MSG = "STEP_EXECUTION_ERROR";

    /**
     * Cria uma exceção com mensagem e causa.
     *
     * @param code descrição do erro
     * @param cause   causa raiz
     */
    public StepException(String code, Throwable cause) {
        super(code, DEFAULT_MSG, cause);
    }

    /**
     * Cria uma exceção apenas com mensagem.
     *
     * @param code descrição do erro
     */
    public StepException(String code) {
        super(code, DEFAULT_MSG);
    }
}
