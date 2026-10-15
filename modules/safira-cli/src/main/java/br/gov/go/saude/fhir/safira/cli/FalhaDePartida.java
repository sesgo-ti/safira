/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import org.springframework.boot.context.properties.bind.BindException;

/**
 * Mensagem curta da falha na partida do Spring: propriedade com valor inválido vira o nome da
 * propriedade (sem os tipos internos do conversor); o resto, a mensagem da causa raiz.
 */
final class FalhaDePartida {

    private FalhaDePartida() {
    }

    static String mensagem(Throwable falha) {
        for (Throwable causa = falha; causa != null; causa = causa.getCause() == causa ? null : causa.getCause()) {
            if (causa instanceof BindException vinculo) {
                return "valor inválido na configuração '" + vinculo.getName()
                        + "' (confira o formato no README e no --config).";
            }
        }
        Throwable raiz = falha;
        while (raiz.getCause() != null && raiz.getCause() != raiz) {
            raiz = raiz.getCause();
        }
        return raiz.getMessage() != null ? raiz.getMessage() : raiz.getClass().getSimpleName();
    }
}
