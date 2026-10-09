/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.token.AbstractKeyStoreTokenConnection;
import eu.europa.esig.dss.token.DSSPrivateKeyEntry;
import eu.europa.esig.dss.token.KSPrivateKeyEntry;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;

import javax.security.auth.DestroyFailedException;

/**
 * Step: cria a assinatura digital (passo 10 da especificação).
 *
 * <p>A chave é usada por um {@code SignatureTokenConnection} do EU DSS ({@link AbstractKeyStoreTokenConnection})
 * sobre um {@link KeyStore} PKCS#12 carregado uma única vez: o PKCS#12 do cliente, ou, para PEM (lido com
 * BouncyCastle), um KeyStore em memória com a entrada única da chave e de {@code chain[0]}. Só a entrada
 * escolhida é decifrada. O valor RS256 ({@code RSASSA-PKCS1-v1_5} com SHA-256, único
 * algoritmo da política 0.2.0 — C18) é produzido sobre o signing input e codificado em Base64Url.
 *
 * <p>O DSS não confere a chave com o certificado nem verifica o valor produzido; por isso o step mantém:
 * chave não RSA → {@code CERT.UNSUPPORTED-ALGORITHM}; chave que não corresponde a {@code chain[0]} →
 * {@code CRYPTO.KEY-INACCESSIBLE} (VULN-A1); valor que o certificado não verifica (pelo
 * {@code JAdESService} do DSS) → {@code CRYPTO.SIGNATURE-CREATION-FAILED}. PKCS#12 sem alias usa a
 * entrada cujo certificado tem a chave pública do signatário.
 *
 * <p><b>Tipos de material suportados:</b> PEM e PKCS#12. PKCS#11 (smartcard/token) e remoto
 * são rejeitados na leitura da requisição.
 */
@StepId("crypto-signing")
public class CryptoSigningStep implements SigningStep {

    private static final Logger log = LoggerFactory.getLogger(CryptoSigningStep.class);

    public static final String SIGNATURE_KEY = "signature";

    private static final String PEM_ALIAS = "signatario";

    // Instância própria: o provider não é registrado na JVM (a icpbrasil-truststore 0.0.2 também não o registra).
    private static final Provider BOUNCY_CASTLE = new BouncyCastleProvider();

    private static final SecureRandom RANDOM = new SecureRandom();

    private final JadesSigningService signingService;

    public CryptoSigningStep() {
        this(new JadesSigningService());
    }

    public CryptoSigningStep(JadesSigningService signingService) {
        this.signingService = signingService;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        byte[] signingInputBytes = context
                .getAttribute(SigningKeys.SIGNING_INPUT_BYTES, byte[].class)
                .orElseThrow(() -> new StepException(
                        SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "Os bytes do signing input não foram encontrados no contexto. "
                                + "Verifique se o step jades-data-to-sign foi executado."));

        CryptoMaterial material = context.getCryptoMaterial();
        if (material == null) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "O material criptográfico não foi fornecido no contexto.");
        }

        X509Certificate signerCertificate = context.getSignerCertificate()
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O certificado do signatário não foi encontrado no contexto. "
                                + "Verifique se o step pkix-chain-validation foi executado."));
        PublicKey signerPublicKey = signerCertificate.getPublicKey();

        try (LoadedKeyStoreToken token = openToken(material, signerCertificate)) {
            KSPrivateKeyEntry entry = selectEntry(token, material, signerPublicKey);
            PrivateKey privateKey = entry.getPrivateKey();

            if (!"RSA".equals(privateKey.getAlgorithm())) {
                return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                        "A política 0.2.0 admite somente RS256 (RSASSA-PKCS1-v1_5 com SHA-256); chave fornecida: "
                                + privateKey.getAlgorithm(), context);
            }
            if (!matches(privateKey, signerPublicKey)) {
                return StepResult.failure(getName(), SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                        "A chave privada fornecida não corresponde à chave pública do certificado do signatário.", context);
            }

            byte[] signatureBytes = sign(token, entry, signingInputBytes);

            // Defesa em profundidade: nunca emitir assinatura que a chave pública do certificado não verifica.
            if (!signingService.isValidSignatureValue(signingInputBytes, signatureBytes, signerCertificate)) {
                return StepResult.failure(getName(), SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A assinatura produzida não é verificável com a chave pública do certificado do signatário.",
                        context);
            }
            String signatureB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(signatureBytes);

            return StepResult.success(getName(), context.toBuilder()
                    .attribute(SIGNATURE_KEY, signatureB64Url)
                    .build());
        } catch (KeyLoadingException e) {
            return StepResult.failure(getName(), e.code, e.getMessage(), context);
        }
    }

    private byte[] sign(LoadedKeyStoreToken token, DSSPrivateKeyEntry entry, byte[] signingInputBytes) {
        try {
            SignatureValue value = token.sign(new ToBeSigned(signingInputBytes), SignatureAlgorithm.RSA_SHA256, entry);
            return value.getValue();
        } catch (Exception e) {
            log.error("Falha na operação de assinatura RS256", e);
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Falha na operação criptográfica de assinatura.", e);
        }
    }

    private LoadedKeyStoreToken openToken(CryptoMaterial material, X509Certificate signer)
            throws KeyLoadingException {
        try {
            return switch (material) {
                case CryptoMaterial.PemMaterial pem -> openPemToken(pem, signer);
                case CryptoMaterial.Pkcs12Material p12 -> openPkcs12Token(p12);
            };
        } catch (KeyLoadingException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Falha ao carregar a chave privada do material criptográfico", e);
            throw new StepException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Não foi possível carregar a chave privada do material criptográfico fornecido.", e);
        }
    }

    private KSPrivateKeyEntry selectEntry(LoadedKeyStoreToken token, CryptoMaterial material,
                                          PublicKey signerPublicKey) throws KeyLoadingException {
        try {
            String alias = material instanceof CryptoMaterial.Pkcs12Material p12 ? p12.alias() : PEM_ALIAS;
            if (alias != null && !alias.isEmpty()) {
                if (token.getKey(alias) instanceof KSPrivateKeyEntry entry) {
                    return entry;
                }
                throw new KeyLoadingException(SignatureExceptionCode.DEVICE_CERTIFICATE_NOT_FOUND,
                        "O alias '" + alias + "' não foi encontrado no PKCS#12 ou não possui chave privada associada.");
            }
            // Escolhe pelo certificado, sem decifrar as demais entradas (cada uma tem seu PBKDF e pode ter outra senha).
            String matching = token.keyAliasFor(signerPublicKey);
            if (matching != null && token.getKey(matching) instanceof KSPrivateKeyEntry entry) {
                return entry;
            }
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Nenhuma chave privada do PKCS#12 corresponde ao certificado do signatário.");
        } catch (KeyLoadingException e) {
            throw e;
        } catch (Exception e) {
            log.warn("Falha ao ler a chave privada do material criptográfico", e);
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Não foi possível ler a chave privada do material criptográfico fornecido.");
        }
    }

    /** Chave privada RSA pertence ao par da chave pública do certificado (mesmo módulo). */
    private static boolean matches(PrivateKey privateKey, PublicKey publicKey) {
        if (privateKey instanceof RSAPrivateCrtKey crt && publicKey instanceof RSAPublicKey rsa) {
            return crt.getModulus().equals(rsa.getModulus()) && crt.getPublicExponent().equals(rsa.getPublicExponent());
        }
        return privateKey instanceof RSAKey key && publicKey instanceof RSAPublicKey rsa
                && key.getModulus().equals(rsa.getModulus());
    }

    private LoadedKeyStoreToken openPkcs12Token(CryptoMaterial.Pkcs12Material p12) throws KeyLoadingException {
        byte[] p12Bytes;
        try {
            p12Bytes = Base64.getDecoder().decode(p12.contentBase64());
        } catch (IllegalArgumentException e) {
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "O conteúdo PKCS#12 não está codificado em Base64 válido.");
        }

        char[] password = p12.password() != null ? p12.password().toCharArray() : new char[0];
        // PasswordProtection clona a senha; o token destrói a cópia no close(), e aqui no caminho de falha.
        PasswordProtection protection = new PasswordProtection(password);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(new ByteArrayInputStream(p12Bytes), password);
            return new LoadedKeyStoreToken(keyStore, protection);
        } catch (Exception e) {
            destroy(protection);
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Não foi possível abrir o PKCS#12 com a senha fornecida.");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    /** Única cola: chave PEM lida pelo BouncyCastle num KeyStore PKCS#12 em memória (entrada única com {@code chain[0]}). */
    private LoadedKeyStoreToken openPemToken(CryptoMaterial.PemMaterial pem, X509Certificate signer) throws Exception {
        PrivateKey privateKey = loadPemPrivateKey(pem);
        char[] ephemeral = Base64.getEncoder().encodeToString(randomBytes(24)).toCharArray();
        PasswordProtection protection = new PasswordProtection(ephemeral);
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, null);
            keyStore.setKeyEntry(PEM_ALIAS, privateKey, ephemeral, new Certificate[]{signer});
            return new LoadedKeyStoreToken(keyStore, protection);
        } catch (Exception e) {
            destroy(protection);
            throw e;
        } finally {
            Arrays.fill(ephemeral, '\0');
        }
    }

    private static void destroy(PasswordProtection protection) {
        try {
            protection.destroy();
        } catch (DestroyFailedException e) {
            log.warn("Não foi possível destruir a senha do material criptográfico");
        }
    }

    private static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        RANDOM.nextBytes(bytes);
        return bytes;
    }

    private PrivateKey loadPemPrivateKey(CryptoMaterial.PemMaterial pem) throws Exception {
        if (pem.privateKey() == null || pem.privateKey().isEmpty()) {
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "A chave PEM não foi fornecida.");
        }
        byte[] pemBytes;
        try {
            pemBytes = Base64.getDecoder().decode(pem.privateKey());
        } catch (IllegalArgumentException e) {
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "A chave PEM não está codificada em Base64 válido.");
        }

        try (PEMParser parser = new PEMParser(
                new InputStreamReader(new ByteArrayInputStream(pemBytes), StandardCharsets.UTF_8))) {
            Object object = parser.readObject();
            if (object == null) {
                throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                        "O conteúdo PEM fornecido está vazio ou não contém um objeto reconhecível.");
            }

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BOUNCY_CASTLE);

            if (object instanceof PEMEncryptedKeyPair encrypted) {
                if (pem.password() == null || pem.password().isEmpty()) {
                    throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                            "A chave PEM está criptografada mas a senha não foi fornecida.");
                }
                char[] password = pem.password().toCharArray();
                try {
                    PEMKeyPair decrypted = encrypted.decryptKeyPair(
                            new JcePEMDecryptorProviderBuilder().setProvider(BOUNCY_CASTLE).build(password));
                    return converter.getKeyPair(decrypted).getPrivate();
                } finally {
                    Arrays.fill(password, '\0');
                }
            } else if (object instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            } else if (object instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }

            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "O conteúdo PEM não contém uma chave privada reconhecível.");
        }
    }

    /**
     * Token do DSS sobre um {@link KeyStore} já carregado (ponto de extensão
     * {@link AbstractKeyStoreTokenConnection}): o PKCS#12 é aberto uma única vez e só a entrada escolhida é decifrada.
     */
    private static final class LoadedKeyStoreToken extends AbstractKeyStoreTokenConnection {

        private final KeyStore keyStore;
        private final PasswordProtection protection;

        LoadedKeyStoreToken(KeyStore keyStore, PasswordProtection protection) {
            this.keyStore = keyStore;
            this.protection = protection;
        }

        @Override
        protected KeyStore getKeyStore() {
            return keyStore;
        }

        @Override
        protected PasswordProtection getKeyProtectionParameter() {
            return protection;
        }

        /** Alias da entrada de chave cujo certificado tem a chave pública informada, sem decifrar nenhuma chave. */
        String keyAliasFor(PublicKey publicKey) throws KeyStoreException {
            Enumeration<String> aliases = keyStore.aliases();
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                Certificate certificate = keyStore.getCertificate(alias);
                if (keyStore.isKeyEntry(alias) && certificate != null
                        && MessageDigest.isEqual(certificate.getPublicKey().getEncoded(), publicKey.getEncoded())) {
                    return alias;
                }
            }
            return null;
        }

        @Override
        public void close() {
            destroy(protection);
        }
    }

    private static class KeyLoadingException extends Exception {
        final SignatureExceptionCode code;

        KeyLoadingException(SignatureExceptionCode code, String message) {
            super(message);
            this.code = code;
        }
    }
}
