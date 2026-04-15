package br.gov.go.saude.fhir.safira.rest.dto;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.validation.constraints.*;

public record ValidationInput(
        @NotBlank String signedDataBase64,
        @NotNull @Min(1751328000L) @Max(4102444800L) Long referenceTimestamp,
        @NotBlank @Pattern(
                regexp = "^https://fhir\\.saude\\.go\\.gov\\.br/r4/seguranca/ImplementationGuide/br\\.go\\.ses\\.seguranca\\|\\d+\\.\\d+\\.\\d+$"
        ) String policyIdentifierUri,
        JsonNode bundle,
        JsonNode provenance
) {}
