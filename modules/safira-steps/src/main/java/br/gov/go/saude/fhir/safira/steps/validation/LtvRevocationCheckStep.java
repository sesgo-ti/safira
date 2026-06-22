package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.CodeableConcept;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;

import java.util.List;

/**
 * Step: verifica revogação LTV dos certificados da cadeia.
 *
 * <p>Stub — a consulta online OCSP/CRL ainda não está implementada.
 * Emite um {@code warning} informativo no contexto e avança o pipeline.
 */
@StepId("validation-ltv-revocation-check")
public class LtvRevocationCheckStep implements ValidationStep {

    private static final String CODE_SYSTEM =
            "https://fhir.saude.go.gov.br/r4/seguranca/CodeSystem/situacao-excepcional-assinatura";

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        context.getWarnings().add(buildStubWarning());
        return StepResult.success(getName(), context);
    }

    private static OperationOutcome.Issue buildStubWarning() {
        Coding coding = Coding.builder()
                .system(CODE_SYSTEM)
                .code(SignatureExceptionCode.REVOCATION.getCode())
                .display(SignatureExceptionCode.REVOCATION.getDisplay())
                .build();
        CodeableConcept details = CodeableConcept.builder()
                .coding(List.of(coding))
                .text(SignatureExceptionCode.REVOCATION.getDisplay())
                .build();
        return OperationOutcome.Issue.builder()
                .severity("warning")
                .code("business-rule")
                .details(details)
                .diagnostics("Verificação completa de revogação (LTV e online) está pendente. "
                        + "Esta execução apenas aceita a estrutura LTV já validada.")
                .build();
    }
}
