package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class JsonCanonicalizationStepTest {

    private SigningStep step;

    @BeforeEach
    void setUp() {
        step = new JsonCanonicalizationStep();
    }

    @Test
    void shouldCanonicalizeValidJsonAndAddToContext() {
        // Arrange
        String rawJson = """
                {
                  "type": "document",
                  "resourceType": "Bundle",
                  "entry": [{
                    "resource": {
                      "id": "1",
                      "resourceType": "Patient",
                      "birthDate": "1990-01-01"
                    }
                  }]
                }""";
                
        String expectedCanonicalJson = """
                {"entry":[{"resource":{"birthDate":"1990-01-01","id":"1","resourceType":"Patient"}}],"resourceType":"Bundle","type":"document"}""";

        SigningContext context = SigningContext.builder()
                .bundle(Bundle.builder().rawJson(rawJson).build())
                .build();

        // Act
        StepResult<SigningContext> result = step.execute(context);

        // Assert
        assertTrue(result.isSuccess(), "Step execution should be successful");
        
        SigningContext updatedContext = ((StepResult.Success<SigningContext>) result).context();
        String canonicalizedJson = updatedContext.getAttribute("canonicalizedJson", String.class).orElse(null);

        assertEquals(expectedCanonicalJson, canonicalizedJson, "JSON should be perfectly canonicalized (RFC 8785)");
    }

    @Test
    void shouldThrowStepExceptionWhenProvidedInvalidJson() {
        // Arrange
        String invalidJson = "{ invalid: format,, }";

        SigningContext context = SigningContext.builder()
                .bundle(Bundle.builder().rawJson(invalidJson).build())
                .build();

        // Act & Assert
        StepException exception = assertThrows(StepException.class, () -> step.execute(context), 
            "Should throw StepException when canonicalizer fails to parse");
            
        assertTrue(exception.getMessage().contains("Erro inesperado na canonicalização do JSON"), 
            "Exception message should indicate canonicalization failure");
    }
}
