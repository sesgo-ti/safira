/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.CodeableConcept;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Step terminal: monta o OperationOutcome final com a issue principal de sucesso e
 * todas as warnings acumuladas durante o pipeline (spec §7).
 */
@StepId("validation-success")
public class ValidationSuccessStep implements ValidationStep {

    private static final String CODE_SYSTEM =
            "https://fhir.saude.go.gov.br/r4/seguranca/CodeSystem/situacao-excepcional-assinatura";
    private static final String SUCCESS_TEXT = "Assinatura digital validada com sucesso";

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        List<OperationOutcome.Issue> issues = new ArrayList<>();
        issues.add(buildMainIssue(context));
        if (context.getWarnings() != null) {
            issues.addAll(context.getWarnings());
        }

        OperationOutcome outcome = OperationOutcome.builder()
                .resourceType("OperationOutcome")
                .issue(List.copyOf(issues))
                .build();

        ValidationContext updated = context.toBuilder()
                .operationOutcome(outcome)
                .build();
        return StepResult.success(getName(), updated);
    }

    private static OperationOutcome.Issue buildMainIssue(ValidationContext context) {
        String alg = extractAlg(context.getProtectedHeader());
        String policy = context.getPolicyIdentifierUri();
        TimestampStrategy strategy = context.getTimestampStrategy();
        String strategyStr = strategy == null ? "null" : strategy.name();

        Coding coding = Coding.builder()
                .system(CODE_SYSTEM)
                .code(SignatureExceptionCode.VALIDATION_SUCCESS.getCode())
                .display(SignatureExceptionCode.VALIDATION_SUCCESS.getDisplay())
                .build();
        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(coding))
                .text(SUCCESS_TEXT)
                .build();
        return OperationOutcome.Issue.builder()
                .severity("information")
                .code("informational")
                .details(details)
                .diagnostics(String.format("alg=%s; policy=%s; strategy=%s", alg, policy, strategyStr))
                .build();
    }

    private static String extractAlg(Map<String, Object> protectedHeader) {
        if (protectedHeader == null) return "null";
        Object alg = protectedHeader.get("alg");
        return alg == null ? "null" : alg.toString();
    }
}
