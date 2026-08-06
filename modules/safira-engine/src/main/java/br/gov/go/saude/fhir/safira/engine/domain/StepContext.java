/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import java.util.Map;
import java.util.Optional;

/**
 * Contrato mínimo de contexto para execução de steps.
 * Provê acesso tipado a atributos genéricos propagados ao longo do pipeline.
 */
public interface StepContext {

    /**
     * Retorna o atributo associado à chave, convertido para o tipo solicitado.
     *
     * @param key  chave do atributo
     * @param type classe do tipo esperado
     * @param <T>  tipo do valor
     * @return valor presente, ou vazio se a chave não existir ou o tipo não bater
     */
    <T> Optional<T> getAttribute(String key, Class<T> type);

    /** Retorna todos os atributos como cópia imutável. */
    Map<String, Object> getAttributes();
}
