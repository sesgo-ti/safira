package br.gov.go.saude.fhir.safira.rest.dto;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ValidationInputTest {

    private static final String VALID_POLICY_URI =
            "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|1.1.0";
    private static final long VALID_TIMESTAMP = 1_800_000_000L;

    private static ValidatorFactory factory;
    private static Validator validator;

    @BeforeAll
    static void setUpValidator() {
        factory = Validation.buildDefaultValidatorFactory();
        validator = factory.getValidator();
    }

    @AfterAll
    static void tearDownValidator() {
        factory.close();
    }

    @Test
    void shouldAcceptMinimalRequiredInput() {
        var input = new ValidationInput(
                "c2lnbmVkRGF0YQ==",
                VALID_TIMESTAMP,
                VALID_POLICY_URI,
                null,
                null
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertEquals(0, violations.size());
    }

    @Test
    void shouldAcceptFullInputWithBundleAndProvenance() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode bundle = mapper.readTree("{\"resourceType\":\"Bundle\"}");
        JsonNode provenance = mapper.readTree("{\"resourceType\":\"Provenance\"}");

        var input = new ValidationInput(
                "c2lnbmVkRGF0YQ==",
                VALID_TIMESTAMP,
                VALID_POLICY_URI,
                bundle,
                provenance
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertEquals(0, violations.size());
    }

    @Test
    void shouldRejectBlankSignedData() {
        var input = new ValidationInput(
                "   ",
                VALID_TIMESTAMP,
                VALID_POLICY_URI,
                null,
                null
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("signedDataBase64")));
    }

    @Test
    void shouldRejectReferenceTimestampBelowMin() {
        var input = new ValidationInput(
                "c2lnbmVkRGF0YQ==",
                1000L,
                VALID_POLICY_URI,
                null,
                null
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("referenceTimestamp")));
    }

    @Test
    void shouldRejectReferenceTimestampAboveMax() {
        var input = new ValidationInput(
                "c2lnbmVkRGF0YQ==",
                5_000_000_000L,
                VALID_POLICY_URI,
                null,
                null
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("referenceTimestamp")));
    }

    @Test
    void shouldRejectInvalidPolicyUri() {
        var input = new ValidationInput(
                "c2lnbmVkRGF0YQ==",
                VALID_TIMESTAMP,
                "not-a-valid-uri",
                null,
                null
        );

        Set<ConstraintViolation<ValidationInput>> violations = validator.validate(input);

        assertTrue(violations.stream()
                .anyMatch(v -> v.getPropertyPath().toString().equals("policyIdentifierUri")));
    }
}
