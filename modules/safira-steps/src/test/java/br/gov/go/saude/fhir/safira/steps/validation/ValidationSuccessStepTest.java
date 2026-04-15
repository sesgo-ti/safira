package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.CodeableConcept;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Coding;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationSuccessStepTest {

    private static final String POLICY_URI = "https://policy|1.0.0";

    private ValidationSuccessStep step;

    @BeforeEach
    void setUp() {
        step = new ValidationSuccessStep();
    }

    @Test
    void shouldBuildOutcomeWithMainIssueAndNoWarnings() {
        ValidationContext ctx = baseContext(new ArrayList<>());

        StepResult<ValidationContext> result = step.execute(ctx);

        OperationOutcome outcome = assertSuccess(result).getOperationOutcome();
        assertNotNull(outcome);
        assertEquals(1, outcome.issue().size());
        OperationOutcome.Issue main = outcome.issue().get(0);
        assertEquals("information", main.severity());
        assertEquals("informational", main.code());
        assertEquals(SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                main.details().coding().get(0).code());
        assertEquals("Assinatura digital validada com sucesso", main.details().text());
    }

    @Test
    void shouldBuildOutcomeWithMainIssueAndAccumulatedWarnings() {
        List<OperationOutcome.Issue> warnings = new ArrayList<>();
        warnings.add(buildWarning("WARN-A"));
        warnings.add(buildWarning("WARN-B"));
        ValidationContext ctx = baseContext(warnings);

        StepResult<ValidationContext> result = step.execute(ctx);

        OperationOutcome outcome = assertSuccess(result).getOperationOutcome();
        assertEquals(3, outcome.issue().size());
        assertEquals(SignatureExceptionCode.VALIDATION_SUCCESS.getCode(),
                outcome.issue().get(0).details().coding().get(0).code());
        assertEquals("WARN-A", outcome.issue().get(1).details().coding().get(0).code());
        assertEquals("WARN-B", outcome.issue().get(2).details().coding().get(0).code());
    }

    @Test
    void shouldIncludeAlgPolicyAndStrategyInDiagnostics() {
        ValidationContext ctx = baseContext(new ArrayList<>());

        StepResult<ValidationContext> result = step.execute(ctx);

        OperationOutcome.Issue main = assertSuccess(result).getOperationOutcome().issue().get(0);
        String diag = main.diagnostics();
        assertTrue(diag.contains("alg=RS256"));
        assertTrue(diag.contains("policy=" + POLICY_URI));
        assertTrue(diag.contains("strategy=IAT"));
    }

    private static ValidationContext baseContext(List<OperationOutcome.Issue> warnings) {
        Map<String, Object> protectedHeader = new LinkedHashMap<>();
        protectedHeader.put("alg", "RS256");
        return ValidationContext.builder()
                .policyIdentifierUri(POLICY_URI)
                .protectedHeader(protectedHeader)
                .timestampStrategy(TimestampStrategy.IAT)
                .warnings(warnings)
                .build();
    }

    private static OperationOutcome.Issue buildWarning(String code) {
        Coding coding = Coding.builder().code(code).build();
        CodeableConcept details = CodeableConcept.builder().coding(List.of(coding)).build();
        return OperationOutcome.Issue.builder()
                .severity("warning")
                .code("business-rule")
                .details(details)
                .build();
    }

    private static ValidationContext assertSuccess(StepResult<ValidationContext> result) {
        StepResult.Success<ValidationContext> s = assertInstanceOf(StepResult.Success.class, result);
        return s.context();
    }
}
