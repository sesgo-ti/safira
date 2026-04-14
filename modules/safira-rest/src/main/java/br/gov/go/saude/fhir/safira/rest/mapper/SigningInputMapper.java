package br.gov.go.saude.fhir.safira.rest.mapper;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.rest.dto.SigningInput;
import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.stereotype.Component;

@Component
public class SigningInputMapper {

    private final SafiraOperationalConfigProperties operationalConfig;

    public SigningInputMapper(SafiraOperationalConfigProperties operationalConfig) {
        this.operationalConfig = operationalConfig;
    }

    public SigningContext toContext(SigningInput input) {
        return SigningContext.builder()
                .bundle(mapBundle(input.bundle()))
                .provenance(mapProvenance(input.provenance()))
                .rawCertificateChain(input.certificateChain())
                .referenceTimestamp(input.referenceTimestamp())
                .strategy(TimestampStrategy.valueOf(input.strategy().toUpperCase()))
                .policyIdentifierUri(input.policyIdentifierUri())
                .cryptoMaterial(mapCryptoMaterial(input.signerCryptoMaterial()))
                .operationalConfig(operationalConfig)
                .build();
    }

    private Bundle mapBundle(JsonNode node) {
        return Bundle.fromJson(node.toString());
    }

    private Provenance mapProvenance(JsonNode node) {
        return Provenance.fromJson(node.toString());
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
