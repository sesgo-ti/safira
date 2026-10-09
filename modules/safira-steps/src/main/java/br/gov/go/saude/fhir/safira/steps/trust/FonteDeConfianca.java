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

    /** Acervo vigente, ou vazio quando indisponível. */
    Optional<AcervoDeConfianca> atual();
}
