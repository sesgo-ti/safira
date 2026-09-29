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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

import java.io.ByteArrayInputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.util.Base64;
import java.util.Enumeration;

/**
 * Step: cria a assinatura digital (passo 10 da especificação).
 *
 * <p>Carrega a chave privada do {@link CryptoMaterial} e executa RSASSA-PKCS1-v1_5 com SHA-256
 * ({@code RS256}, único algoritmo da política 0.2.0 — C18) sobre os bytes do signing input,
 * codificando o resultado em Base64Url. Chave não RSA resulta em {@code CERT.UNSUPPORTED-ALGORITHM}.
 *
 * <p><b>Tipos de material suportados:</b> PEM e PKCS#12. PKCS#11 (smartcard/token) e remoto
 * são rejeitados na leitura da requisição.
 */
@StepId("crypto-signing")
public class CryptoSigningStep implements SigningStep {

    public static final String SIGNATURE_KEY = "signature";


    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        byte[] signingInputBytes = context
                .getAttribute(SigningKeys.SIGNING_INPUT_BYTES, byte[].class)
                .orElseThrow(() -> new StepException(
                        SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "Os bytes do signing input não foram encontrados no contexto. "
                                + "Verifique se o step signing-input foi executado."));

        CryptoMaterial material = context.getCryptoMaterial();
        if (material == null) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "O material criptográfico não foi fornecido no contexto.");
        }

        PrivateKey privateKey;
        try {
            privateKey = loadPrivateKey(material);
        } catch (KeyLoadingException e) {
            return StepResult.failure(getName(), e.code, e.getMessage(), context);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Erro ao carregar a chave privada: " + e.getMessage(), e);
        }

        if (!"RSA".equals(privateKey.getAlgorithm())) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                    "A política 0.2.0 admite somente RS256 (RSASSA-PKCS1-v1_5 com SHA-256); chave fornecida: "
                            + privateKey.getAlgorithm(), context);
        }

        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(privateKey);
            sig.update(signingInputBytes);
            String signatureB64Url = Base64.getUrlEncoder().withoutPadding().encodeToString(sig.sign());

            SigningContext updated = context.toBuilder()
                    .attribute(SIGNATURE_KEY, signatureB64Url)
                    .build();
            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro na operação de assinatura: " + e.getMessage(), e);
        }
    }

    private PrivateKey loadPrivateKey(CryptoMaterial material) throws Exception {
        return switch (material) {
            case CryptoMaterial.PemMaterial pem -> loadPemPrivateKey(pem);
            case CryptoMaterial.Pkcs12Material p12 -> loadPkcs12PrivateKey(p12);
        };
    }

    private PrivateKey loadPemPrivateKey(CryptoMaterial.PemMaterial pem) throws Exception {
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

            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME);

            if (object instanceof PEMEncryptedKeyPair encrypted) {
                if (pem.password() == null || pem.password().isEmpty()) {
                    throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                            "A chave PEM está criptografada mas a senha não foi fornecida.");
                }
                PEMKeyPair decrypted = encrypted.decryptKeyPair(
                        new JcePEMDecryptorProviderBuilder().build(pem.password().toCharArray()));
                return converter.getKeyPair(decrypted).getPrivate();
            } else if (object instanceof PEMKeyPair keyPair) {
                return converter.getKeyPair(keyPair).getPrivate();
            } else if (object instanceof PrivateKeyInfo info) {
                return converter.getPrivateKey(info);
            }

            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "O conteúdo PEM não contém uma chave privada reconhecível: " + object.getClass().getSimpleName());
        }
    }

    private PrivateKey loadPkcs12PrivateKey(CryptoMaterial.Pkcs12Material p12) throws Exception {
        byte[] p12Bytes;
        try {
            p12Bytes = Base64.getDecoder().decode(p12.contentBase64());
        } catch (IllegalArgumentException e) {
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "O conteúdo PKCS#12 não está codificado em Base64 válido.");
        }

        char[] password = p12.password() != null ? p12.password().toCharArray() : new char[0];

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try {
            keyStore.load(new ByteArrayInputStream(p12Bytes), password);
        } catch (Exception e) {
            throw new KeyLoadingException(SignatureExceptionCode.CRYPTO_KEY_INACCESSIBLE,
                    "Não foi possível abrir o PKCS#12 com a senha fornecida: " + e.getMessage());
        }

        String alias = p12.alias();
        if (alias != null && !alias.isEmpty()) {
            if (!keyStore.containsAlias(alias)) {
                throw new KeyLoadingException(SignatureExceptionCode.DEVICE_CERTIFICATE_NOT_FOUND,
                        "O alias '" + alias + "' não foi encontrado no PKCS#12.");
            }
            if (!keyStore.isKeyEntry(alias)) {
                throw new KeyLoadingException(SignatureExceptionCode.DEVICE_KEY_ACCESS_DENIED,
                        "O alias '" + alias + "' não possui chave privada associada.");
            }
        } else {
            alias = findFirstKeyAlias(keyStore);
            if (alias == null) {
                throw new KeyLoadingException(SignatureExceptionCode.DEVICE_KEY_ACCESS_DENIED,
                        "Nenhuma chave privada foi encontrada no PKCS#12.");
            }
        }

        return (PrivateKey) keyStore.getKey(alias, password);
    }

    private String findFirstKeyAlias(KeyStore keyStore) throws Exception {
        Enumeration<String> aliases = keyStore.aliases();
        while (aliases.hasMoreElements()) {
            String current = aliases.nextElement();
            if (keyStore.isKeyEntry(current)) {
                return current;
            }
        }
        return null;
    }

    private static class KeyLoadingException extends Exception {
        final SignatureExceptionCode code;

        KeyLoadingException(SignatureExceptionCode code, String message) {
            super(message);
            this.code = code;
        }
    }
}
