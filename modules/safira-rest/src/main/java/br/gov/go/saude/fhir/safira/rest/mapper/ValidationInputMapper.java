package br.gov.go.saude.fhir.safira.rest.mapper;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.rest.dto.ValidationInput;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

@Component
public class ValidationInputMapper {

    private final SafiraOperationalConfigProperties operationalConfig;

    public ValidationInputMapper(SafiraOperationalConfigProperties operationalConfig) {
        this.operationalConfig = operationalConfig;
    }

    public ValidationContext toContext(ValidationInput input) {
        return ValidationContext.builder()
                .signedDataBase64(input.signedDataBase64())
                .referenceTimestamp(input.referenceTimestamp())
                .policyIdentifierUri(input.policyIdentifierUri())
                .bundle(mapBundle(input.bundle()))
                .provenance(mapProvenance(input.provenance()))
                .operationalConfig(operationalConfig)
                .build();
    }

    private Bundle mapBundle(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        return Bundle.fromJson(node.toString());
    }

    private Provenance mapProvenance(JsonNode node) {
        if (node == null || node.isNull()) {
            return null;
        }
        return Provenance.fromJson(node.toString());
    }
}
