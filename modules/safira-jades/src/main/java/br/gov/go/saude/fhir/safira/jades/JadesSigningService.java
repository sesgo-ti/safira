/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESSigningTimeType;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.Policy;
import eu.europa.esig.dss.model.SignatureValue;
import eu.europa.esig.dss.model.ToBeSigned;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.spi.DSSUtils;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Produção de assinaturas JAdES-B-B (ETSI TS 119 182-1) via EU DSS, em três fases:
 * {@link #newSession(Request)} → {@link #dataToSign(JadesSigningSession)} →
 * (assinatura externa do material criptográfico) → {@link #sign(JadesSigningSession, byte[])}.
 *
 * <p>A chave privada nunca entra nesta classe: o valor da assinatura é produzido fora
 * (PEM/PKCS#12 hoje; PKCS#11/remoto no futuro) e entregue pronto — o desenho preserva o
 * passo {@code crypto-signing} do Safira e o perfil do IG SES-GO:
 *
 * <ul>
 *   <li>JWS General JSON Serialization (RFC 7515 §7.2.1) — requisito C14;</li>
 *   <li>payload <em>attached</em>: os bytes do SHA-256 das instâncias canonicalizadas
 *       (requisito C15 — sem {@code sigD}, sem {@code crit});</li>
 *   <li>{@code iat} incondicional (ETSI TS 119 182-1 §5.1.11 — obrigatório desde 2025-07-15);</li>
 *   <li>{@code x5c} com a cadeia completa (requisito C17);</li>
 *   <li>{@code sigPId} com o identificador da política (e digest quando disponível).</li>
 * </ul>
 */
public class JadesSigningService {

    /**
     * Parâmetros de criação de uma sessão de assinatura.
     *
     * @param certificateChain      cadeia completa, folha primeiro (requisito C17)
     * @param payload               bytes crus do payload JWS (32 bytes do SHA-256)
     * @param referenceTimestamp    instante declarado da assinatura ({@code iat}), epoch seconds UTC
     * @param policyId              URI da política de assinatura ({@code sigPId.id})
     * @param policyDigestAlgorithm algoritmo do hash do documento da política (opcional)
     * @param policyDigest          hash do documento da política (opcional; habilita {@code digAlg}/{@code digVal})
     */
    public record Request(
            List<X509Certificate> certificateChain,
            byte[] payload,
            long referenceTimestamp,
            String policyId,
            DigestAlgorithm policyDigestAlgorithm,
            byte[] policyDigest) {

        public Request {
            Objects.requireNonNull(certificateChain, "certificateChain não pode ser nulo");
            Objects.requireNonNull(payload, "payload não pode ser nulo");
            Objects.requireNonNull(policyId, "policyId não pode ser nulo");
            if (certificateChain.isEmpty()) {
                throw new IllegalArgumentException("certificateChain deve conter ao menos o certificado do signatário");
            }
        }
    }

    /**
     * Monta os parâmetros JAdES-B-B e congela a sessão de assinatura.
     */
    public JadesSigningSession newSession(Request request) {
        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);

        // iat incondicional (independente da estratégia de carimbo) — ETSI TS 119 182-1 §5.1.11 e §6.3
        parameters.setJadesSigningTimeType(JAdESSigningTimeType.IAT);
        parameters.bLevel().setSigningDate(Date.from(Instant.ofEpochSecond(request.referenceTimestamp())));

        // Header mínimo do perfil SES-GO: alg, x5c (cadeia completa), iat, sigPId
        parameters.setIncludeCertificateChain(true);
        parameters.setIncludeSignatureType(false);
        parameters.setIncludeKeyIdentifier(false);

        parameters.setSigningCertificate(new CertificateToken(request.certificateChain().get(0)));
        parameters.setCertificateChain(request.certificateChain().stream()
                .map(CertificateToken::new)
                .toList());

        Policy policy = new Policy();
        policy.setId(request.policyId());
        if (request.policyDigest() != null && request.policyDigestAlgorithm() != null) {
            policy.setDigestAlgorithm(request.policyDigestAlgorithm());
            policy.setDigestValue(request.policyDigest().clone());
        }
        parameters.bLevel().setSignaturePolicy(policy);

        return new JadesSigningSession(parameters, request.payload());
    }

    /**
     * Bytes a assinar (signing input JWS: {@code ASCII(BASE64URL(protected) '.' BASE64URL(payload))}).
     */
    public byte[] dataToSign(JadesSigningSession session) {
        ToBeSigned toBeSigned = newService().getDataToSign(document(session), session.parameters());
        return toBeSigned.getBytes();
    }

    /**
     * Monta o JWS General JSON Serialization com o valor de assinatura produzido externamente.
     *
     * <p>Para ECDSA o valor deve estar em DER (formato JCA); o DSS o transcodifica para
     * R||S conforme o JWS. Para RSA (PKCS#1 v1.5) o valor é usado como está.
     *
     * @param session        sessão criada em {@link #newSession(Request)}
     * @param signatureValue assinatura dos bytes de {@link #dataToSign(JadesSigningSession)}
     * @return JWS em General JSON Serialization (JSON compacto)
     */
    public String sign(JadesSigningSession session, byte[] signatureValue) {
        SignatureAlgorithm algorithm = resolveAlgorithm(session);
        SignatureValue value = new SignatureValue(algorithm, signatureValue);
        DSSDocument signed = newService().signDocument(document(session), session.parameters(), value);
        return new String(DSSUtils.toByteArray(signed), StandardCharsets.UTF_8);
    }

    private SignatureAlgorithm resolveAlgorithm(JadesSigningSession session) {
        CertificateToken signer = session.parameters().getSigningCertificate();
        if (signer.getPublicKey() instanceof ECPublicKey) {
            return SignatureAlgorithm.ECDSA_SHA256;
        }
        return SignatureAlgorithm.RSA_SHA256;
    }

    private JAdESService newService() {
        // Assinatura B-B não consulta fontes externas: verifier vazio é suficiente.
        return new JAdESService(new CommonCertificateVerifier());
    }

    private DSSDocument document(JadesSigningSession session) {
        return new InMemoryDocument(session.payload());
    }
}
