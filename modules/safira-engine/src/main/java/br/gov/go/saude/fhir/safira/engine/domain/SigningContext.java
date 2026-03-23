/*
 * Copyright (c) 2025-2026.
 *
 * Fábrica de Software - Instituto de Informática (UFG)
 * Secretaria Estadual de Saúde de Goiás (SES-GO)
 *
 */

package br.gov.go.saude.fhir.safira.engine.domain;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Contexto imutável para consumo de steps do fluxo de assinatura.
 *
 * <p>
 * Carrega dados do Bundle, credenciais de assinatura e resultados
 * intermediários. Cada step pode adicionar dados, retornando nova instância.
 * </p>
 *
 * @since 1.0.0
 */
public final class SigningContext implements StepContext {

    private final String bundleJson;
    private final String provenanceJson;
    private final CryptoMaterial cryptoMaterial;
    private final List<String> rawCertificateChain;
    private final Long referenceTimestamp;
    private final TimestampStrategy strategy;
    private final String policyIdentifierUri;
    private final OperationalConfig operationalConfig;
    
    private final PrivateKey privateKey;
    private final X509Certificate[] certificateChain;
    private final Instant signingTime;
    private final Map<String, Object> attributes;

    private SigningContext(Builder builder) {
        this.bundleJson = builder.bundleJson;
        this.provenanceJson = builder.provenanceJson;
        this.cryptoMaterial = builder.cryptoMaterial;
        this.rawCertificateChain = builder.rawCertificateChain;
        this.referenceTimestamp = builder.referenceTimestamp;
        this.strategy = builder.strategy;
        this.policyIdentifierUri = builder.policyIdentifierUri;
        this.operationalConfig = builder.operationalConfig;
        
        this.privateKey = builder.privateKey;
        this.certificateChain = builder.certificateChain;
        this.signingTime = builder.signingTime;
        this.attributes = Collections.unmodifiableMap(new HashMap<>(builder.attributes));
    }

    public String getBundleJson() { return bundleJson; }
    public String getProvenanceJson() { return provenanceJson; }
    public CryptoMaterial getCryptoMaterial() { return cryptoMaterial; }
    public List<String> getRawCertificateChain() { return rawCertificateChain; }
    public Long getReferenceTimestamp() { return referenceTimestamp; }
    public TimestampStrategy getStrategy() { return strategy; }
    public String getPolicyIdentifierUri() { return policyIdentifierUri; }
    public OperationalConfig getOperationalConfig() { return operationalConfig; }

    public Optional<PrivateKey> getPrivateKey() {
        return Optional.ofNullable(privateKey);
    }

    public Optional<X509Certificate[]> getCertificateChain() {
        return Optional.ofNullable(certificateChain);
    }

    public Optional<X509Certificate> getSignerCertificate() {
        return getCertificateChain()
                .filter(chain -> chain.length > 0)
                .map(chain -> chain[0]);
    }

    public Instant getSigningTime() {
        return signingTime;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> Optional<T> getAttribute(String key, Class<T> type) {
        Object value = attributes.get(key);
        if (value != null && type.isInstance(value)) {
            return Optional.of((T) value);
        }
        return Optional.empty();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    public Builder toBuilder() {
        return new Builder()
                .bundleJson(this.bundleJson)
                .provenanceJson(this.provenanceJson)
                .cryptoMaterial(this.cryptoMaterial)
                .rawCertificateChain(this.rawCertificateChain)
                .referenceTimestamp(this.referenceTimestamp)
                .strategy(this.strategy)
                .policyIdentifierUri(this.policyIdentifierUri)
                .operationalConfig(this.operationalConfig)
                .privateKey(this.privateKey)
                .certificateChain(this.certificateChain)
                .signingTime(this.signingTime)
                .attributes(this.attributes);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String bundleJson;
        private String provenanceJson;
        private CryptoMaterial cryptoMaterial;
        private List<String> rawCertificateChain;
        private Long referenceTimestamp;
        private TimestampStrategy strategy;
        private String policyIdentifierUri;
        private OperationalConfig operationalConfig;
        
        private PrivateKey privateKey;
        private X509Certificate[] certificateChain;
        private Instant signingTime;
        private final Map<String, Object> attributes = new HashMap<>();

        public Builder() {}

        public Builder bundleJson(String bundleJson) { this.bundleJson = bundleJson; return this; }
        public Builder provenanceJson(String provenanceJson) { this.provenanceJson = provenanceJson; return this; }
        public Builder cryptoMaterial(CryptoMaterial cryptoMaterial) { this.cryptoMaterial = cryptoMaterial; return this; }
        public Builder rawCertificateChain(List<String> rawCertificateChain) { this.rawCertificateChain = rawCertificateChain; return this; }
        public Builder referenceTimestamp(Long referenceTimestamp) { this.referenceTimestamp = referenceTimestamp; return this; }
        public Builder strategy(TimestampStrategy strategy) { this.strategy = strategy; return this; }
        public Builder policyIdentifierUri(String policyIdentifierUri) { this.policyIdentifierUri = policyIdentifierUri; return this; }
        public Builder operationalConfig(OperationalConfig config) { this.operationalConfig = config; return this; }

        public Builder privateKey(PrivateKey privateKey) { this.privateKey = privateKey; return this; }
        public Builder certificateChain(X509Certificate[] certificateChain) { this.certificateChain = certificateChain; return this; }
        public Builder signingTime(Instant signingTime) { this.signingTime = signingTime; return this; }

        public Builder attribute(String key, Object value) {
            this.attributes.put(key, value);
            return this;
        }

        public Builder attributes(Map<String, Object> attributes) {
            this.attributes.putAll(attributes);
            return this;
        }

        public SigningContext build() {
            return new SigningContext(this);
        }
    }
}
