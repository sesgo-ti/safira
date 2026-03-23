package br.gov.go.saude.fhir.safira.engine.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Propriedades de configuração operacional do engine de assinatura digital.
 * <p>
 * Mapeadas a partir do prefixo {@code safira.operational} no {@code application.yml}
 * de qualquer consumidor Spring Boot que inclua o {@code safira-engine} como dependência.
 * <p>
 * (padrão Spring Boot AutoConfiguration), sem necessidade de declaração manual pelo consumidor.
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "safira.operational")
public class SafiraOperationalConfigProperties {

    private VerificationProps verification = new VerificationProps();
    private TrustStoreProps trustStore = new TrustStoreProps();
    private SecurityLimitsProps security = new SecurityLimitsProps();
    private MiddlewareCryptoProps middlewareCrypto = new MiddlewareCryptoProps();

    // -------------------------------------------------------------------------
    // Verificação: OCSP, CRL e TSA
    // -------------------------------------------------------------------------

    @Getter @Setter
    public static class VerificationProps {
        /** Tempo de vida (segundos) para respostas OCSP em cache. Padrão: 3600. Intervalo: [300, 86400]. */
        private Integer ocspCacheTtl = 3600;

        /** Tempo de vida (segundos) para listas CRL em cache. Padrão: 3600. Intervalo: [300, 86400]. */
        private Integer crlCacheTtl = 3600;

        /** Timeout (segundos) para consultas OCSP. Padrão: 20. Intervalo: [5, 120]. */
        private Integer ocspTimeout = 20;

        /** Timeout (segundos) para download de CRL. Padrão: 20. Intervalo: [5, 120]. */
        private Integer crlTimeout = 20;

        /** Timeout (segundos) para comunicação com o serviço TSA. Padrão: 20. Intervalo: [5, 120]. */
        private Integer tsaTimeout = 20;

        /** Número máximo de tentativas em caso de falha de rede. Padrão: 3. Intervalo: [1, 5]. */
        private Integer maxRetries = 3;

        /** Intervalo (segundos) entre tentativas de retry. Padrão: 2. Intervalo: [1, 10]. */
        private Integer retryInterval = 2;

        /** URL do serviço TSA (RFC 3161). Obrigatória quando a estratégia de timestamp é TSA. Deve iniciar com https://. */
        private String tsaUrl;

        /** (Opcional) Usuário para autenticação HTTP Basic no serviço TSA. */
        private String tsaUsername;

        /** (Opcional) Senha para autenticação HTTP Basic no serviço TSA. */
        private String tsaPassword;
    }

    // -------------------------------------------------------------------------
    // Trust Store: gerenciamento de certificados ICP-Brasil
    // -------------------------------------------------------------------------

    @Getter @Setter
    public static class TrustStoreProps {
        /** URL do .zip com certificados das ACs vigentes da ICP-Brasil. */
        private String icpbrasilUrlCertificados;

        /** URL do arquivo SHA-512 do zip da ICP-Brasil. */
        private String icpbrasilUrlHash512;

        /** Timeout (segundos) para acesso às URLs ICP-Brasil. Padrão: 30. */
        private Integer timeout = 30;

        /** Número máximo de tentativas para obtenção de conteúdo da ICP-Brasil. Padrão: 3. */
        private Integer maxRetries = 3;

        /**
         * Intervalos de backoff entre tentativas, em segundos separados por espaço.
         * Exemplo: "2 5 10"
         */
        private String backoff;

        /**
         * Estratégia de armazenamento do truststore.
         * Opções: {@code memoria} | {@code diretorio} | {@code s3}
         */
        private String repositorio;

        /** Diretório local onde dados do truststore são depositados (repositorio=diretorio). */
        private String diretorio;

        /** Bucket S3 onde dados são depositados (repositorio=s3). */
        private String bucket;

        /** Intervalo (minutos) para verificação de novo conteúdo na ICP-Brasil. Padrão: 1440. */
        private Integer refresh = 1440;

        /** TTL de alerta (minutos): sinaliza conteúdo local próximo do vencimento. Padrão: 2880. */
        private Integer ttlCritico = 2880;

        /** TTL máximo (minutos): após este ponto o truststore local é ignorado. Padrão: 10080. */
        private Integer ttlMaximo = 10080;
    }

    // -------------------------------------------------------------------------
    // Limites de segurança para processamento de Bundles FHIR
    // -------------------------------------------------------------------------

    @Getter @Setter
    public static class SecurityLimitsProps {
        /** Número máximo de entradas no Bundle. Padrão: 1000. Intervalo: [100, 10000]. */
        private Integer maxEntriesBundle = 1000;

        /** Tamanho máximo do Bundle em bytes. Padrão: 52428800 (50 MB). Intervalo: [1048576, 209715200]. */
        private Integer maxBundleSize = 52428800;

        /** Timeout (segundos) para verificação do Bundle. Padrão: 10. Intervalo: [5, 300]. */
        private Integer timoutVerificationBundle = 10;
    }

    // -------------------------------------------------------------------------
    // Middleware criptográfico PKCS#11 (SMARTCARD / TOKEN)
    // -------------------------------------------------------------------------

    @Getter @Setter
    public static class MiddlewareCryptoProps {
        private LibraryProps library = new LibraryProps();
        private Pkcs11Props pkcs11 = new Pkcs11Props();
        private SessionProps session = new SessionProps();
        private ConnectivityProps connectivity = new ConnectivityProps();

        @Getter @Setter
        public static class LibraryProps {
            /** Caminho absoluto para a biblioteca PKCS#11 (.dll/.so). Deve existir e ser acessível. */
            private String path;

            /** Especificação de arquitetura: "32" ou "64". Opcional. */
            private String architecture;
        }

        @Getter @Setter
        public static class Pkcs11Props {
            /** Identificador do slot (inteiro não negativo). Opcional, padrão: descoberta automática. */
            private Integer slotId;

            /** Label do token (até 32 caracteres UTF-8). Opcional. */
            private String tokenLabel;

            /**
             * Mecanismos PKCS#11 suportados.
             * Valores válidos: {@code CKM_RSA_PKCS} | {@code CKM_ECDSA}
             */
            private List<String> mecanismos;
        }

        @Getter @Setter
        public static class SessionProps {
            /**
             * Tipo de acesso à sessão PKCS#11.
             * Valores: {@code read-only} | {@code read-write}. Padrão: "read-only".
             */
            private String modo = "read-only";

            /** Timeout de inatividade (segundos). Padrão: 300. Intervalo: [60, 3600]. */
            private Integer timeoutInatividade = 300;

            /** Tentativas de autenticação (PIN) antes de bloquear o token. Padrão: 3. Intervalo: [1, 10]. */
            private Integer tentativasAutenticacao = 3;
        }

        @Getter @Setter
        public static class ConnectivityProps {
            /** Timeout (segundos) para conexão com o middleware. Padrão: 10. Intervalo: [3, 60]. */
            private Integer timeoutConexao = 10;

            /** Intervalo (segundos) entre tentativas de reconexão. Padrão: 2. Intervalo: [1, 30]. */
            private Integer intervaloRetry = 2;

            /** Número máximo de retries. Padrão: 3. Intervalo: [0, 10]. */
            private Integer maximoRetries = 3;
        }
    }
}
