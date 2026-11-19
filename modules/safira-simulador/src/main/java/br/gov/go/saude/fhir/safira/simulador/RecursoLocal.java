/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

/**
 * Restringe os recursos da simulação (âncoras, ACs, LCRs) a {@code file:} e {@code classpath:}.
 * URL remota é recusada antes de qualquer acesso: evita SSRF no startup e raiz de confiança
 * obtida sem integridade.
 */
final class RecursoLocal {

    private RecursoLocal() {
    }

    static void exigir(Resource recurso, String propriedade) {
        if (!(recurso instanceof ClassPathResource) && !recurso.isFile()) {
            throw new IllegalStateException(propriedade + ": somente recursos locais (file: ou classpath:) são aceitos: "
                    + recurso.getDescription());
        }
    }
}
