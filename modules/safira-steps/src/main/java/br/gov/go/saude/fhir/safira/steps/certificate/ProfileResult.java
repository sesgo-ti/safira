/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

/** Resultado da avaliação do certificado folha contra o perfil ICP-Brasil da política 0.2.0. */
public sealed interface ProfileResult {

    /**
     * @param identity  identidade protegida extraída do certificado
     * @param policyOid OID completo da política aceita pela allowlist
     */
    record Eligible(SignerIdentity identity, String policyOid) implements ProfileResult {
    }

    record Rejected(SignatureExceptionCode code, String diagnostics) implements ProfileResult {
    }
}
