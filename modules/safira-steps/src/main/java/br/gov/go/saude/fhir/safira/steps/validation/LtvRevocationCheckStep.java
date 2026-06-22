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
 * Stub atual — verificação completa é TODO.
 *
 * TODO(revocation): consulta online OCSP via AIA extension (OID 1.3.6.1.5.5.7.48.1)
 * TODO(revocation): consulta online CRL via CDP extension (OID 2.5.29.31)
 * TODO(revocation): cache com metadata (fetchedAt / nextUpdate / expiresAt)
 * TODO(revocation): aplicar revocationPolicy (STRICT / SOFT_FAIL / WARN) em falhas de fetch
 * TODO(revocation): aplicar ocspUnknownHandling (TREAT_AS_REVOKED / TREAT_AS_WARNING)
 * TODO(revocation): materializar codigos CERT.REVOKED, REVOCATION.OCSP-UNAVAILABLE,
 *                   REVOCATION.CRL-UNAVAILABLE, REVOCATION.CACHE-EXPIRED quando full-check
 *                   estiver implementado
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
