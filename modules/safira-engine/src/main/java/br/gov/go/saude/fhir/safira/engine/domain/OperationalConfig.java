package br.gov.go.saude.fhir.safira.engine.domain;

import java.util.List;

public record OperationalConfig(
    VerificationConfig verification,
    TrustStoreConfig trustStore,
    SecurityLimitsConfig security,
    CryptoMiddlewareConfig middlewareCrypto
) {

    public record VerificationConfig(
        Integer ocspCacheTtl,
        Integer crlCacheTtl,
        Integer ocspTimeout,
        Integer crlTimeout,
        Integer tsaTimeout,
        Integer maxRetries,
        Integer retryInterval,
        String tsaUrl,
        String tsaUsername,
        String tsaPassword
    ) {}

    public record TrustStoreConfig(
        String icpbrasilUrlCertificados,
        String icpbrasilUrlHash512,
        Integer timeout,
        Integer maxRetries,
        String backoff,
        String repositorio,
        String diretorio,
        String bucket,
        Integer refresh,
        Integer ttlCritico,
        Integer ttlMaximo
    ) {}

    public record SecurityLimitsConfig(
        Integer maxEntriesBundle,
        Integer maxBundleSize,
        Integer timoutVerificationBundle
    ) {}

    public record CryptoMiddlewareConfig(
        LibraryConfig library,
        Pkcs11Config pkcs11,
        SessionConfig session,
        ConnectivityConfig connectivity
    ) {
        public record LibraryConfig(String path, String architecture) {}
        public record Pkcs11Config(Integer slotId, String tokenLabel, List<String> mecanismos) {}
        public record SessionConfig(String modo, Integer timeoutInatividade, Integer tentativasAutenticacao) {}
        public record ConnectivityConfig(Integer timeoutConexao, Integer intervaloRetry, Integer maximoRetries) {}
    }
}
