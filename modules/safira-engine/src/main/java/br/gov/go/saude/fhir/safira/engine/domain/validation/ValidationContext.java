package br.gov.go.saude.fhir.safira.engine.domain.validation;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepContext;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Bundle;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome.Issue;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.Provenance;
import lombok.Builder;
import lombok.Singular;
import lombok.Value;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@Value
@Builder(toBuilder = true)
public class ValidationContext implements StepContext {
    // Input fields (from DTO)
    String signedDataBase64;
    Long referenceTimestamp;
    String policyIdentifierUri;
    Bundle bundle;
    Provenance provenance;

    // Shared / operational state
    SafiraOperationalConfigProperties operationalConfig;

    PrivateKey privateKey;
    @Builder.Default
    List<X509Certificate> certificateChain = Collections.emptyList();
    Instant signingTime;

    // Populated during pipeline (JWS decoding/parsing)
    String rawJwsJson;
    String rawProtectedHeaderBase64Url;
    Map<String, Object> protectedHeader;
    Map<String, Object> unprotectedHeader;
    String payloadBase64Url;
    byte[] signatureBytes;

    // Timestamp resolution
    TimestampStrategy timestampStrategy;
    Long resolvedSignatureTimestamp;

    // Mutable list so steps can append warnings without rebuilding the context.
    @Builder.Default
    List<Issue> warnings = new ArrayList<>();

    OperationOutcome operationOutcome;

    @Singular("attribute")
    Map<String, Object> attributes;

    public Optional<PrivateKey> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    public Optional<List<X509Certificate>> getCertificateChain() {
        return Optional.ofNullable(certificateChain);
    }

    public Optional<X509Certificate> getSignerCertificate() {
        List<X509Certificate> chain = this.certificateChain;

        if (chain == null || chain.isEmpty()) {
            return Optional.empty();
        }

        // The signer certificate is typically the first one in the chain
        return Optional.of(chain.get(0));
    }

    public ValidationContext addCertificate(X509Certificate cert) {
        List<X509Certificate> existing = this.certificateChain == null
                ? Collections.emptyList()
                : this.certificateChain;

        List<X509Certificate> newChain = Stream.concat(existing.stream(), Stream.of(cert)).toList();

        return this.toBuilder()
                .certificateChain(newChain)
                .build();
    }

    @Override
    public <T> Optional<T> getAttribute(String key, Class<T> type) {
        Object v = attributes == null ? null : attributes.get(key);
        if (v == null || !type.isInstance(v)) return Optional.empty();
        return Optional.of(type.cast(v));
    }
}
