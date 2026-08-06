/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/**
 * Resultado da execução de um step: {@link Success} com contexto atualizado
 * ou {@link Failure} com código de erro estruturado.
 *
 * @param <C> tipo do contexto associado ao step
 */
public sealed interface StepResult<C> permits StepResult.Success, StepResult.Failure {

    String stepName();

    C context();

    boolean isSuccess();

    default boolean isFailure() {
        return !isSuccess();
    }

    static <C> StepResult<C> success(String stepName, C context) {
        return new Success<>(stepName, context);
    }

    static <C> StepResult<C> failure(String stepName, SignatureExceptionCode code, String diagnostics, C context) {
        return new Failure<>(stepName, code, diagnostics, context);
    }

    record Success<C>(String stepName, C context) implements StepResult<C> {
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

    record Failure<C>(String stepName, SignatureExceptionCode code, String diagnostics, C context) implements StepResult<C> {
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
