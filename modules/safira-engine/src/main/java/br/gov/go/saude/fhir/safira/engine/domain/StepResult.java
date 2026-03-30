package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/**
 * Representa o resultado de um step de validação ou processamento no
 * pipeline.
 *
 * <p>
 * Esta interface selada (sealed) permite apenas dois tipos de resultados:
 * </p>
 * <ul>
 * <li>{@link Success} - Operação bem-sucedida, contém o contexto atualizado</li>
 * <li>{@link Failure} - Operação falhou, contém código do erro</li>
 * </ul>
 *
 * <p>
 * Uso típico:
 * </p>
 *
 * <pre>{@code
 * StepResult result = step.execute(context);
 * String stepName = result.stepName();
 * return switch (result) {
 *     case StepResult.Success success -> processNext(success.context());
 *     case StepResult.Failure failure -> handleError(failure.code());
 * };
 * }</pre>
 *
 * @param <C> Contexto associado ao step e ao resultado do step
 */
public sealed interface StepResult<C> permits StepResult.Success, StepResult.Failure {

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
    boolean isSuccess();

    /**
     * Verifica se o resultado representa falha.
     *
     * @return {@code true} se for um resultado de falha, {@code false} caso
     *         contrário
     */
    default boolean isFailure() {
        return !isSuccess();
    }

    /**
     * Cria um resultado de sucesso com o contexto fornecido.
     *
     * @param stepName o nome do step que produziu o resultado
     * @param context  o contexto resultante da operação bem-sucedida
     * @param <C>      tipo do contexto
     * @return instância de {@link Success} contendo o contexto
     */
    static <C> StepResult<C> success(String stepName, C context) {
        return new Success<>(stepName, context);
    }

    /**
     * Cria um resultado de falha com o código do erro.
     *
     * @param stepName    o nome do step que produziu o resultado
     * @param code        o código do erro que identifica a falha
     * @param diagnostics detalhes específicos e contextuais do erro
     * @param context     o contexto resultante da operação bem-sucedida
     * @param <C>         tipo do contexto
     * @return instância de {@link Failure} contendo o erro
     */
    static <C> StepResult<C> failure(String stepName, SignatureExceptionCode code, String diagnostics, C context) {
        return new Failure<>(stepName, code, diagnostics, context);
    }

    /**
     * Resultado de sucesso contendo o contexto atualizado.
     *
     * @param stepName o nome do step que produziu o resultado
     * @param context  o contexto resultante da operação
     * @param <C>      tipo do contexto
     */
    record Success<C>(String stepName, C context) implements StepResult<C> {
        /**
         * Cria um resultado de sucesso.
         *
         * @param stepName o nome do step, não pode ser nulo
         * @param context  o contexto, não pode ser nulo
         * @throws NullPointerException se stepName ou context forem nulos
         */
        public Success {
            if (stepName == null) {
                throw new NullPointerException("stepName não pode ser nulo");
            }
            if (context == null) {
                throw new NullPointerException("context não pode ser nulo");
            }
        }

        @Override
        public boolean isSuccess() {
            return true;
        }
    }

    /**
     * Resultado de falha contendo detalhes do erro.
     *
     * @param stepName    o nome do step que produziu o resultado
     * @param code        o código oficial do CodeSystem da Segurança
     * @param diagnostics os detalhes contextuais adicionais
     * @param context     o contexto do pipeline
     * @param <C>         tipo do contexto
     */
    record Failure<C>(String stepName, SignatureExceptionCode code, String diagnostics, C context) implements StepResult<C> {
        /**
         * Cria um resultado de falha.
         */
        public Failure {
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
        public boolean isSuccess() {
            return false;
        }
    }
}
