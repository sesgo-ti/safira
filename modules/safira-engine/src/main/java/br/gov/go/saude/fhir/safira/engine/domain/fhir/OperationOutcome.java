/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.util.List;

/**
 * Representação do tipo FHIR {@code OperationOutcome}, restrita ao perfil de
 * situações excepcionais na criação e validação de assinaturas digitais.
 */
@Builder
public record OperationOutcome(
        String resourceType,
        String id,
        List<Issue> issue
) {
    @Builder
    public record Issue(
            String severity,
            String code,
            CodeableConcept details,
            String diagnostics,
            List<String> location
    ) {}

    /**
     * Cria um {@code OperationOutcome} conforme o perfil de segurança GO SES.
     *
     * @param severity      severidade FHIR: {@code "fatal"}, {@code "error"}, {@code "warning"} ou {@code "information"}
     * @param typeCode      tipo de issue FHIR padrão (ex: {@code "processing"}, {@code "invalid"})
     * @param exceptionCode código do CodeSystem de situações excepcionais (ex: {@code "CERT.EXPIRED"})
     * @param text          texto legível do erro, usado em {@code details.text}
     * @param diagnostics   informação diagnóstica adicional e contextual
     * @return instância de {@link OperationOutcome} pronta para serialização FHIR
     */
    public static OperationOutcome createSignatureError(
            String severity,
            String typeCode,
            String exceptionCode,
            String text,
            String diagnostics) {

        Coding exceptionCoding = Coding.builder()
                .system("https://fhir.saude.go.gov.br/r4/seguranca/CodeSystem/situacao-excepcional-assinatura")
                .code(exceptionCode)
                .build();

        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(exceptionCoding))
                .text(text)
                .build();

        Issue issue = Issue.builder()
                .severity(severity)
                .code(typeCode)
                .details(details)
                .diagnostics(diagnostics)
                .build();

        return OperationOutcome.builder()
                .resourceType("OperationOutcome")
                .issue(List.of(issue))
                .build();
    }
}
