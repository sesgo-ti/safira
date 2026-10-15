/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.dss;

import br.gov.go.saude.fhir.safira.jades.StrictValidationPolicies;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;

import java.util.Optional;

/**
 * Política de validação do DSS com a lista explícita dos OIDs de
 * {@code safira.policy.accepted-certificate-policies}, montada uma vez na construção dos steps.
 */
public final class PoliticaDeValidacaoDss {

    private PoliticaDeValidacaoDss() {
    }

    /**
     * Vazio quando a allowlist não tem OID válido: a aplicação sobe e o step recusa a operação
     * (falha fechada), como a validação de configuração do contexto.
     */
    public static Optional<StrictValidationPolicies> da(SafiraPolicyProperties policy) {
        try {
            return Optional.of(StrictValidationPolicies.comPoliticasAceitas(
                    policy.acceptedCertificatePolicies().stream().map(AcceptedCertificatePolicy::oid).toList()));
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }
}
