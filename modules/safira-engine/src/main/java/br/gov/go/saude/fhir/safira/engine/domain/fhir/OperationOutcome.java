package br.gov.go.saude.fhir.safira.engine.domain.fhir;

import lombok.Builder;

import java.util.List;

/**
 * Representation of the FHIR OperationOutcome data type, optimized for the
 * specialized profile reporting exceptional situations during digital signature creation.
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
     * Helper factory to create a compliant OperationOutcome based on the GO SES Security IG rules.
     * @param severity "fatal", "error", "warning", or "information"
     * @param typeCode The standard FHIR issue type code (e.g. "processing", "invalid", "security")
     * @param exceptionCode The specialized signature exception code (e.g. "CERT.EXPIRED")
     * @param text A plain text representation of the error (details.text)
     * @param diagnostics Additional diagnostic information
     * @return OperationOutcome instance
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
