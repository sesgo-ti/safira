/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;

/**
 * Interface genérica para steps.
 *
 * <p>
 * Cada step executa uma etapa do processo sobre um contexto. Se a
 * execução foi concluída, na perspectiva do negócio, então retorna
 * um {@link ResultStep}. Este objeto pode indicar sucesso
 * (com contexto atualizado) ou falha (com detalhes do erro).
 * Em caso de situação excepcional deve gerar {@link StepException}.
 * </p>
 *
 * <p>
 * Steps devem ser funções puras sem side-effects.
 * </p>
 *
 * @param <C> o tipo do contexto utilizado pelo step, que deve
 *            estender de {@link StepContext}.
 */
@FunctionalInterface
public interface Step<C extends StepContext> {

    /**
     * Executa o step sobre o contexto.
     *
     * @param context contexto
     * @return resultado da execução ({@link ResultStep.Ok} ou
     *         {@link ResultStep.Fail})
     */
    ResultStep<C> execute(C context) throws StepException;

    /**
     * Retorna o nome do step para logging/diagnóstico.
     *
     * @return nome do step
     */
    default String getName() {
        return this.getClass().getSimpleName();
    }
}
