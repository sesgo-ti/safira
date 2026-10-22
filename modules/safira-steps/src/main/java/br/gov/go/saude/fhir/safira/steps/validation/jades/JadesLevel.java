/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

/** Níveis locais admitidos pela política 0.2.0 (validar 2.4). */
public enum JadesLevel {

    /** Sem membro {@code header}. */
    B_B("JAdES-B-B"),
    /** {@code header} = {@code etsiU} em claro com um único {@code sigTst}. */
    B_T("JAdES-B-T");

    private final String label;

    JadesLevel(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }
}
