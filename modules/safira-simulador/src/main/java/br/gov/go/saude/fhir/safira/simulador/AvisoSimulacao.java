/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;

import java.util.ArrayList;
import java.util.List;

/**
 * Marca o {@code OperationOutcome} de sucesso de {@code /validar} produzido no modo simulação com
 * uma issue informativa adicional, para que o resultado nunca seja confundido com uma validação
 * ICP-Brasil real. Registrado só quando {@code safira.simulacao.enabled=true}.
 */
public final class AvisoSimulacao {

    public static final String TEXTO = "SIMULAÇÃO — sem validade jurídica ICP-Brasil";

    // DIVERGENCIA-IG: o CodeSystem não tem código próprio para simulação; a issue reutiliza
    // VALIDATION.SUCCESS (information) para manter o OperationOutcome conforme ao perfil.
    private static final OperationOutcome.Issue ISSUE = OperationOutcome.createSignatureError(
            SignatureExceptionCode.VALIDATION_SUCCESS.getSeverity(), "informational",
            SignatureExceptionCode.VALIDATION_SUCCESS.getCode(), TEXTO,
            "Modo simulação ativo (safira.simulacao.enabled=true): confiança em raízes próprias ("
                    + GeradorPkiSimulada.MARCA + ") no lugar do acervo ICP-Brasil.").issue().getFirst();

    /** Acrescenta a issue de simulação ao final das issues existentes. */
    public OperationOutcome marcar(OperationOutcome outcome) {
        List<OperationOutcome.Issue> issues = new ArrayList<>(outcome.issue());
        issues.add(ISSUE);
        return new OperationOutcome(outcome.resourceType(), outcome.id(), List.copyOf(issues));
    }
}
