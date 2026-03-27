/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import java.util.Map;
import java.util.Optional;

/**
 * Interface base para contextos de steps.
 * 
 * <p>
 * Define o contrato mínimo para acesso a atributos genéricos em contextos
 * de execução de steps.
 * </p>
 */
public interface StepContext {

    /**
     * Obtém um atributo do contexto.
     *
     * @param key  chave do atributo
     * @param type tipo esperado
     * @param <T>  tipo do valor
     * @return valor do atributo, ou vazio se não existir
     */
    <T> Optional<T> getAttribute(String key, Class<T> type);

    /**
     * Retorna todos os atributos (cópia imutável).
     *
     * @return mapa de atributos
     */
    Map<String, Object> getAttributes();
}
