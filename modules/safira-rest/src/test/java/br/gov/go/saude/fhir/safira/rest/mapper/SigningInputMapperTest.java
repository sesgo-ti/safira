package br.gov.go.saude.fhir.safira.rest.mapper;

import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SigningInputMapperTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SigningInputMapper mapper = new SigningInputMapper();

    @Test
    void shouldMapSigningInputToContextCorrectly() throws Exception {
        // Arrange
        String bundleJson = """
                {
                  "resourceType": "Bundle",
                  "id": "123",
                  "entry": [
                    {
                      "fullUrl": "urn:uuid:abc",
                      "resource": {"resourceType": "Patient"}
                    },
                    {
                      "fullUrl": "urn:uuid:def",
                      "resource": {
                        "resourceType": "Provenance",
                        "target": [
                          {
                            "reference": "urn:uuid:abc"
                          }
                        ]
                      }
                    }
                  ]
                }
                """;

        String provenanceJson = """
                {
                  "resourceType": "Provenance",
                  "target": [
                    {
                      "reference": "urn:uuid:abc"
                    }
                  ]
                }
                """;

        SigningInput.CryptoMaterialInput pemMaterial = new SigningInput.PemCryptoMaterial("base64pem", "pass");

        SigningInput input = new SigningInput(
                objectMapper.readTree(bundleJson),
                objectMapper.readTree(provenanceJson),
                pemMaterial,
                List.of("cert1", "cert2"),
                1751328000L,
                "iat",
                "https://fhir.saude.go.gov.br/r4/seguranca/ImplementationGuide/br.go.ses.seguranca|0.1.0"
        );

        // Act
        SigningContext context = mapper.toContext(input);

        // Assert
        assertNotNull(context);
        assertEquals(1751328000L, context.getReferenceTimestamp());
        assertEquals(TimestampStrategy.IAT, context.getStrategy());
        assertEquals(2, context.getRawCertificateChain().size());

        // Validate Bundle
        assertNotNull(context.getBundle());
        assertEquals("Bundle", context.getBundle().resourceType());
        assertEquals("123", context.getBundle().id());
        assertEquals(2, context.getBundle().entry().size());
        assertEquals("urn:uuid:abc", context.getBundle().entry().get(0).fullUrl());
        assertTrue(context.getBundle().entry().get(0).resource().containsKey("resourceType"));
        assertEquals("urn:uuid:def", context.getBundle().entry().get(1).fullUrl());
        assertEquals("Provenance", context.getBundle().entry().get(1).resource().get("resourceType"));
        assertNotNull(context.getBundle().rawJson());

        // Validate Provenance
        assertNotNull(context.getProvenance());
        assertEquals("Provenance", context.getProvenance().resourceType());
        assertEquals(1, context.getProvenance().target().size());
        assertEquals("urn:uuid:abc", context.getProvenance().target().get(0).reference());
        assertNotNull(context.getProvenance().rawJson());
    }
}
