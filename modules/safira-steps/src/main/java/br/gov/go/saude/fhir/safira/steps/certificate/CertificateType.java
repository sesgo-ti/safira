/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import java.util.Set;

/**
 * Categorias de certificado folha ICP-Brasil aceitas pela política 0.2.0 (C16, C18, C19).
 *
 * <p>No YAML os valores são escritos como no IG ({@code A3}, {@code A4}, {@code SE-S},
 * {@code SE-H}); o binding relaxado do Spring converte {@code SE-S} em {@link #SE_S}.
 */
public enum CertificateType {

    A3("A3", "2.16.76.1.2.3.", true, Set.of(2048)),
    A4("A4", "2.16.76.1.2.4.", true, Set.of(2048, 4096)),
    SE_S("SE-S", "2.16.76.1.2.201.", false, Set.of(2048)),
    SE_H("SE-H", "2.16.76.1.2.202.", false, Set.of(2048));

    private final String label;
    private final String branchPrefix;
    private final boolean naturalPerson;
    private final Set<Integer> allowedRsaSizes;

    CertificateType(String label, String branchPrefix, boolean naturalPerson, Set<Integer> allowedRsaSizes) {
        this.label = label;
        this.branchPrefix = branchPrefix;
        this.naturalPerson = naturalPerson;
        this.allowedRsaSizes = allowedRsaSizes;
    }

    /** Rótulo do IG ({@code A3}, {@code SE-S}...). */
    public String label() {
        return label;
    }

    /** Ramo do OID de política, com o ponto final: o OID completo é o ramo seguido de um arco. */
    public String branchPrefix() {
        return branchPrefix;
    }

    /** A3/A4: pessoa física (CPF, assinatura); SE-S/SE-H: pessoa jurídica (CNPJ, selo). */
    public boolean isNaturalPerson() {
        return naturalPerson;
    }

    public Set<Integer> allowedRsaSizes() {
        return allowedRsaSizes;
    }

    /** OID com exatamente sete arcos numéricos no ramo desta categoria. */
    public boolean matchesBranch(String oid) {
        return oid != null
                && oid.matches("^\\d+(\\.\\d+){6}$")
                && oid.startsWith(branchPrefix)
                && oid.substring(branchPrefix.length()).matches("\\d+");
    }
}
