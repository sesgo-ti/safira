package br.gov.go.saude.fhir.safira.engine.domain.signing;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepContext;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import lombok.Builder;
import lombok.Singular;
import lombok.Value;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Value
@Builder(toBuilder = true)
public class SigningContext implements StepContext {

    String rawBundleJson;
    String rawProvenanceJson;
    CryptoMaterial cryptoMaterial;
    List<String> rawCertificateChain;
    Long referenceTimestamp;
    TimestampStrategy strategy;
    String policyIdentifierUri;
    SafiraOperationalConfigProperties operationalConfig;

    PrivateKey privateKey;
    X509Certificate[] certificateChain;
    Instant signingTime;

    @Singular("attribute")
    Map<String, Object> attributes;

    public Optional<PrivateKey> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    public Optional<X509Certificate[]> getCertificateChain() {
        return Optional.ofNullable(certificateChain);
    }

    public Optional<X509Certificate> getSignerCertificate() {
        X509Certificate[] chain = this.certificateChain;

        if (chain == null || chain.length == 0) {
            return Optional.empty();
        }

        // The signer certificate is typically the first one in the chain
        return Optional.of(chain[0]);
    }

    public SigningContext addCertificate(X509Certificate cert) {
        X509Certificate[] newChain;

        if (this.certificateChain == null) {
            newChain = new X509Certificate[]{cert};
        } else {
            newChain = new X509Certificate[this.certificateChain.length + 1];
            System.arraycopy(this.certificateChain, 0, newChain, 0, this.certificateChain.length);
            newChain[this.certificateChain.length] = cert;
        }

        return this.toBuilder()
                .certificateChain(newChain)
                .build();
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getAttribute(String key, Class<T> type) {
        Object value = attributes.get(key);
        if (type.isInstance(value)) {
            return Optional.of((T) value);
        }
        return Optional.empty();
    }
}