package br.gov.go.saude.fhir.safira.engine.domain;

/**
 * Representa o resultado de um step de validação ou processamento no
 * pipeline.
 *
 * <p>
 * Esta interface selada (sealed) permite apenas dois tipos de resultados:
 * </p>
 * <ul>
 * <li>{@link Ok} - Operação bem-sucedida, contém o contexto atualizado</li>
 * <li>{@link Fail} - Operação falhou, contém código do erro</li>
 * </ul>
 *
 * <p>
 * Uso típico:
 * </p>
 *
 * <pre>{@code
 * ResultStep result = step.execute(context);
 * String stepName = result.stepName();
 * return switch (result) {
 *     case ResultStep.Ok ok -> processNext(ok.context());
 *     case ResultStep.Fail fail -> handleError(fail.code());
 * };
 * }</pre>
 *
 * @param <C> Contexto associado ao step e ao resultado do step
 */
public sealed interface ResultStep<C> permits ResultStep.Ok, ResultStep.Fail {

    /**
     * Retorna o nome do step que produziu este resultado.
     *
     * @return o nome do step
     */
    String stepName();

    /**
     * Retorna o contexto associado a este resultado.
     *
     * @return o contexto
     */
    C context();

    /**
     * Verifica se o resultado representa sucesso.
     *
     * @return {@code true} se for um resultado de sucesso, {@code false} caso
     *         contrário
     */
    boolean isOk();

    /**
     * Verifica se o resultado representa falha.
     *
     * @return {@code true} se for um resultado de falha, {@code false} caso
     *         contrário
     */
    default boolean isFail() {
        return !isOk();
    }

    /**
     * Cria um resultado de sucesso com o contexto fornecido.
     *
     * @param stepName o nome do step que produziu o resultado
     * @param context  o contexto resultante da operação bem-sucedida
     * @param <C>      tipo do contexto
     * @return instância de {@link Ok} contendo o contexto
     */
    static <C> ResultStep<C> ok(String stepName, C context) {
        return new Ok<>(stepName, context);
    }

    /**
     * Cria um resultado de falha com o código do erro.
     *
     * @param stepName o nome do step que produziu o resultado
     * @param code     o código do erro que identifica a falha
     * @param context  o contexto resultante da operação bem-sucedida
     * @param <C>      tipo do contexto
     * @return instância de {@link Fail} contendo o erro
     */
    static <C> ResultStep<C> fail(String stepName, String code, C context) {
        return new Fail<>(stepName, code, context);
    }

    /**
     * Resultado de sucesso contendo o contexto atualizado.
     *
     * @param stepName o nome do step que produziu o resultado
     * @param context  o contexto resultante da operação
     * @param <C>      tipo do contexto
     */
    record Ok<C>(String stepName, C context) implements ResultStep<C> {
        /**
         * Cria um resultado de sucesso.
         *
         * @param stepName o nome do step, não pode ser nulo
         * @param context  o contexto, não pode ser nulo
         * @throws NullPointerException se stepName ou context forem nulos
         */
        public Ok {
            if (stepName == null) {
                throw new NullPointerException("stepName não pode ser nulo");
            }
            if (context == null) {
                throw new NullPointerException("context não pode ser nulo");
            }
        }

        @Override
        public boolean isOk() {
            return true;
        }
    }

    /**
     * Resultado de falha contendo detalhes do erro.
     *
     * <p>O parâmetro de tipo {@code C} não é usado diretamente, mas é necessário
     * para manter compatibilidade com {@code ResultStep<C>}.</p>
     *
     * @param stepName o nome do step que produziu o resultado
     * @param code     o código do erro que causou a falha
     * @param <C>      tipo do contexto (não usado, mantido para compatibilidade)
     */
    record Fail<C>(String stepName, String code, C context) implements ResultStep<C> {
        /**
         * Cria um resultado de falha.
         *
         * @param stepName o nome do step, não pode ser nulo
         * @param code     o código do erro, não pode ser nulo
         * @throws NullPointerException se stepName ou code forem nulos
         */
        public Fail {
            if (stepName == null) {
                throw new NullPointerException("stepName não pode ser nulo");
            }
            if (code == null) {
                throw new NullPointerException("code não pode ser nulo");
            }
            if (context == null) {
                throw new NullPointerException("context não pode ser nulo");
            }
        }

        @Override
        public boolean isOk() {
            return false;
        }
    }
}