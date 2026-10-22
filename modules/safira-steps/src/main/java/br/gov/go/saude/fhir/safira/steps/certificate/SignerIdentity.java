/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

/**
 * Identidade protegida do titular do certificado folha: CPF (A3/A4) ou CNPJ (SE-S/SE-H),
 * somente dígitos, no formato de {@code Signature.who.identifier}.
 */
public record SignerIdentity(CertificateType type, String system, String value) {

    public static final String CPF_SYSTEM = "urn:brasil:cpf";
    public static final String CNPJ_SYSTEM = "urn:brasil:cnpj";
}
