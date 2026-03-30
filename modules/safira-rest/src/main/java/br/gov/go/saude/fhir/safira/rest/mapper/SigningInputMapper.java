package br.gov.go.saude.fhir.safira.rest.mapper;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Reference;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.stream.StreamSupport;

@Component
public class SigningInputMapper {

    private final ObjectMapper objectMapper = new ObjectMapper();

    public SigningContext toContext(SigningInput input) {
        return SigningContext.builder()
                .bundle(mapBundle(input.bundle()))
                .provenance(mapProvenance(input.provenance()))
                .rawCertificateChain(input.certificateChain())
                .referenceTimestamp(input.referenceTimestamp())
                .strategy(TimestampStrategy.valueOf(input.strategy().toUpperCase()))
                .policyIdentifierUri(input.policyIdentifierUri())
                .cryptoMaterial(mapCryptoMaterial(input.signerCryptoMaterial()))
                .build();
    }

    private Bundle mapBundle(JsonNode node) {
        var entries = StreamSupport.stream(node.path("entry").spliterator(), false)
                .map(e -> Bundle.BundleEntry.builder()
                        .fullUrl(e.path("fullUrl").asText(null))
                        .resource(objectMapper.convertValue(e.path("resource"), new TypeReference<Map<String, Object>>() {}))
                        .build())
                .toList();

        return Bundle.builder()
                .resourceType(node.path("resourceType").asText(null))
                .id(node.path("id").asText(null))
                .entry(entries)
                .rawJson(node.toString())
                .build();
    }

    private Provenance mapProvenance(JsonNode node) {
        var targets = StreamSupport.stream(node.path("target").spliterator(), false)
                .map(t -> Reference.builder()
                        .reference(t.path("reference").asText(null))
                        .type(t.path("type").asText(null))
                        .display(t.path("display").asText(null))
                        .build())
                .toList();

        return Provenance.builder()
                .resourceType(node.path("resourceType").asText(null))
                .id(node.path("id").asText(null))
                .target(targets)
                .rawJson(node.toString())
                .build();
    }

    private CryptoMaterial mapCryptoMaterial(SigningInput.CryptoMaterialInput input) {
        if (input instanceof SigningInput.PemCryptoMaterial pem) {
            return new CryptoMaterial.PemMaterial(pem.privateKeyBase64(), pem.password());
        } else if (input instanceof SigningInput.Pkcs12CryptoMaterial pkcs12) {
            return new CryptoMaterial.Pkcs12Material(pkcs12.contentBase64(), pkcs12.password(), pkcs12.alias());
        } else {
            throw new UnsupportedOperationException("The selected cryptographic material (" + input.getClass().getSimpleName() + ") has not been fully mapped in the Signature Engine yet.");
        }
    }
}
