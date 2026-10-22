/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import java.util.Optional;

/**
 * Porta de confiança do Safira: entrega o acervo vigente de certificados.
 *
 * <p>Um {@code Optional} vazio significa acervo indisponível; nesse caso as operações
 * de assinatura e validação devem falhar fechado, nunca prosseguir sem confiança.
 */
public interface FonteDeConfianca {

    /**
     * Acervo vigente, ou vazio quando indisponível.
     *
     * <p>Chamadas sucessivas podem devolver gerações diferentes; o consumidor chama uma vez por
     * operação e usa só aquele snapshot. A implementação deve ser thread-safe e barata. Falha ao
     * obter o acervo vira {@code Optional.empty()}, nunca exceção: o fail-closed não pode depender
     * do chamador.
     */
    Optional<AcervoDeConfianca> atual();
}
