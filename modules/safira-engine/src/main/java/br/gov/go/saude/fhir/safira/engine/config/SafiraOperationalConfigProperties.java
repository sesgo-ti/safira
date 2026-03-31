package br.gov.go.saude.fhir.safira.engine.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 * Propriedades de configuração operacional do engine de assinatura digital.
 * <p>
 * Mapeadas a partir do prefixo {@code safira.operational} no {@code application.yml}
 * de qualquer consumidor Spring Boot que inclua o {@code safira-engine} como dependência.
 * <p>
 * (padrão Spring Boot AutoConfiguration), sem necessidade de declaração manual pelo consumidor.
 */
@ConfigurationProperties(prefix = "safira.operational")
public record SafiraOperationalConfigProperties(

        @DefaultValue VerificationProps verification,
        @DefaultValue TrustStoreProps trustStore,
        @DefaultValue SecurityLimitsProps security,
        @DefaultValue MiddlewareCryptoProps middlewareCrypto

) {

    // -------------------------------------------------------------------------
    // Verificação: OCSP, CRL e TSA
    // -------------------------------------------------------------------------

    /**
     * @param ocspCacheTtl  Tempo de vida (segundos) para respostas OCSP em cache. Padrão: 3600. Intervalo: [300, 86400].
     * @param crlCacheTtl   Tempo de vida (segundos) para listas CRL em cache. Padrão: 3600. Intervalo: [300, 86400].
     * @param ocspTimeout   Timeout (segundos) para consultas OCSP. Padrão: 20. Intervalo: [5, 120].
     * @param crlTimeout    Timeout (segundos) para download de CRL. Padrão: 20. Intervalo: [5, 120].
     * @param tsaTimeout    Timeout (segundos) para comunicação com o serviço TSA. Padrão: 20. Intervalo: [5, 120].
     * @param maxRetries    Número máximo de tentativas em caso de falha de rede. Padrão: 3. Intervalo: [1, 5].
     * @param retryInterval Intervalo (segundos) entre tentativas de retry. Padrão: 2. Intervalo: [1, 10].
     * @param tsaUrl        URL do serviço TSA (RFC 3161). Obrigatória quando a estratégia de timestamp é TSA. Deve iniciar com https://.
     * @param tsaUsername   (Opcional) Usuário para autenticação HTTP Basic no serviço TSA.
     * @param tsaPassword   (Opcional) Senha para autenticação HTTP Basic no serviço TSA.
     */
    public record VerificationProps(
            @DefaultValue("3600") Integer ocspCacheTtl,
            @DefaultValue("3600") Integer crlCacheTtl,
            @DefaultValue("20")   Integer ocspTimeout,
            @DefaultValue("20")   Integer crlTimeout,
            @DefaultValue("20")   Integer tsaTimeout,
            @DefaultValue("3")    Integer maxRetries,
            @DefaultValue("2")    Integer retryInterval,
            String tsaUrl,
            String tsaUsername,
            String tsaPassword
    ) {}

    // -------------------------------------------------------------------------
    // Trust Store: gerenciamento de certificados ICP-Brasil
    // -------------------------------------------------------------------------

    /**
     * @param icpbrasilUrlCertificados URL do .zip com certificados das ACs vigentes da ICP-Brasil.
     * @param icpbrasilUrlHash512      URL do arquivo SHA-512 do zip da ICP-Brasil.
     * @param timeout                  Timeout (segundos) para acesso às URLs ICP-Brasil. Padrão: 30.
     * @param maxRetries               Número máximo de tentativas para obtenção de conteúdo da ICP-Brasil. Padrão: 3.
     * @param backoff                  Intervalos de backoff entre tentativas, em segundos separados por espaço. Ex: "2 5 10".
     * @param repositorio              Estratégia de armazenamento do truststore. Opções: {@code memoria} | {@code diretorio} | {@code s3}.
     * @param diretorio                Diretório local onde dados do truststore são depositados (repositorio=diretorio).
     * @param bucket                   Bucket S3 onde dados são depositados (repositorio=s3).
     * @param refresh                  Intervalo (minutos) para verificação de novo conteúdo na ICP-Brasil. Padrão: 1440.
     * @param ttlCritico               TTL de alerta (minutos): sinaliza conteúdo local próximo do vencimento. Padrão: 2880.
     * @param ttlMaximo                TTL máximo (minutos): após este ponto o truststore local é ignorado. Padrão: 10080.
     * @param minimumCertificateDate   Data mínima de emissão do certificado (epoch seconds). Certificados emitidos antes desta data
     *                                 são rejeitados por não atenderem aos requisitos de segurança vigentes. Padrão: 1751328000 (2025-07-01T00:00:00Z).
     */
    public record TrustStoreProps(
            String icpbrasilUrlCertificados,
            String icpbrasilUrlHash512,
            @DefaultValue("30")    Integer timeout,
            @DefaultValue("3")     Integer maxRetries,
            String backoff,
            String repositorio,
            String diretorio,
            String bucket,
            @DefaultValue("1440")  Integer refresh,
            @DefaultValue("2880")  Integer ttlCritico,
            @DefaultValue("10080") Integer ttlMaximo,
            @DefaultValue("1751328000") Long minimumCertificateDate
    ) {}

    // -------------------------------------------------------------------------
    // Limites de segurança para processamento de Bundles FHIR
    // -------------------------------------------------------------------------

    /**
     * @param maxEntriesBundle        Número máximo de entradas no Bundle. Padrão: 1000. Intervalo: [100, 10000].
     * @param maxBundleSize           Tamanho máximo do Bundle em bytes. Padrão: 52428800 (50 MB). Intervalo: [1048576, 209715200].
     * @param timoutVerificationBundle Timeout (segundos) para verificação do Bundle. Padrão: 10. Intervalo: [5, 300].
     */
    public record SecurityLimitsProps(
            @DefaultValue("1000")     Integer maxEntriesBundle,
            @DefaultValue("52428800") Integer maxBundleSize,
            @DefaultValue("10")       Integer timoutVerificationBundle
    ) {}

    // -------------------------------------------------------------------------
    // Middleware criptográfico PKCS#11 (SMARTCARD / TOKEN)
    // -------------------------------------------------------------------------

    public record MiddlewareCryptoProps(
            @DefaultValue LibraryProps library,
            @DefaultValue Pkcs11Props pkcs11,
            @DefaultValue SessionProps session,
            @DefaultValue ConnectivityProps connectivity
    ) {

        /**
         * @param path         Caminho absoluto para a biblioteca PKCS#11 (.dll/.so). Deve existir e ser acessível.
         * @param architecture Especificação de arquitetura: "32" ou "64". Opcional.
         */
        public record LibraryProps(
                String path,
                String architecture
        ) {}

        /**
         * @param slotId      Identificador do slot (inteiro não negativo). Opcional, padrão: descoberta automática.
         * @param tokenLabel  Label do token (até 32 caracteres UTF-8). Opcional.
         * @param mecanismos  Mecanismos PKCS#11 suportados. Valores válidos: {@code CKM_RSA_PKCS} | {@code CKM_ECDSA}.
         */
        public record Pkcs11Props(
                Integer slotId,
                String tokenLabel,
                List<String> mecanismos
        ) {}

        /**
         * @param modo                   Tipo de acesso à sessão PKCS#11. Valores: {@code read-only} | {@code read-write}. Padrão: "read-only".
         * @param timeoutInatividade     Timeout de inatividade (segundos). Padrão: 300. Intervalo: [60, 3600].
         * @param tentativasAutenticacao Tentativas de autenticação (PIN) antes de bloquear o token. Padrão: 3. Intervalo: [1, 10].
         */
        public record SessionProps(
                @DefaultValue("read-only") String modo,
                @DefaultValue("300")       Integer timeoutInatividade,
                @DefaultValue("3")         Integer tentativasAutenticacao
        ) {}

        /**
         * @param timeoutConexao Timeout (segundos) para conexão com o middleware. Padrão: 10. Intervalo: [3, 60].
         * @param intervaloRetry Intervalo (segundos) entre tentativas de reconexão. Padrão: 2. Intervalo: [1, 30].
         * @param maximoRetries  Número máximo de retries. Padrão: 3. Intervalo: [0, 10].
         */
        public record ConnectivityProps(
                @DefaultValue("10") Integer timeoutConexao,
                @DefaultValue("2")  Integer intervaloRetry,
                @DefaultValue("3")  Integer maximoRetries
        ) {}
    }
}
