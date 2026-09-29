/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import eu.europa.esig.dss.enumerations.DigestAlgorithm;
import eu.europa.esig.dss.enumerations.JWSSerializationType;
import eu.europa.esig.dss.enumerations.ObjectIdentifierQualifier;
import eu.europa.esig.dss.enumerations.SignatureAlgorithm;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SignaturePackaging;
import eu.europa.esig.dss.jades.JAdESSignatureParameters;
import eu.europa.esig.dss.jades.JAdESSigningTimeType;
import eu.europa.esig.dss.jades.signature.JAdESService;
import eu.europa.esig.dss.model.CommonCommitmentType;
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
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;

/**
 * Produção de assinaturas JAdES-B-B (ETSI TS 119 182-1) da política 0.2.0 via EU DSS, em três
 * fases: {@link #newSession(Request)} → {@link #dataToSign(JadesSigningSession)} → (assinatura
 * externa RS256) → {@link #sign(JadesSigningSession, byte[])}.
 *
 * <p>A chave privada nunca entra nesta classe. Perfil produzido:
 * <ul>
 *   <li>JWS General JSON Serialization com payload <em>attached</em> (sem {@code sigD}, {@code crit},
 *       {@code cty}, {@code kid} ou {@code typ});</li>
 *   <li>protected header {@code {alg, x5t#S256, x5c, iat, sigPId, srCms}} com {@code alg=RS256},
 *       {@code sigPId={"id":{"id":<URI>}}} e {@code srCms} de <em>Verification Signature</em>.</li>
 * </ul>
 */
public class JadesSigningService {

    /** OID de <em>Verification Signature</em> (ASTM E1762-95) — {@code srCms[0].commId.id}. */
    public static final String VERIFICATION_SIGNATURE_OID = "1.2.840.10065.1.12.1.5";

    /**
     * Parâmetros de criação de uma sessão de assinatura.
     *
     * @param certificateChain   cadeia completa, folha primeiro, terminando na raiz
     * @param payload            bytes crus do payload JWS (SHA-256 do artefato enquadrado)
     * @param referenceTimestamp instante declarado da assinatura ({@code iat}), epoch seconds UTC
     * @param policyId           URI da política de assinatura ({@code sigPId.id.id})
     */
    public record Request(
            List<X509Certificate> certificateChain,
            byte[] payload,
            long referenceTimestamp,
            String policyId) {

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
     *
     * @throws IllegalArgumentException se a chave do signatário não for RSA (a política só admite RS256)
     */
    public JadesSigningSession newSession(Request request) {
        X509Certificate signer = request.certificateChain().getFirst();
        if (!(signer.getPublicKey() instanceof RSAPublicKey)) {
            throw new IllegalArgumentException("A política 0.2.0 admite somente RS256; chave do signatário: "
                    + signer.getPublicKey().getAlgorithm());
        }
        JAdESSignatureParameters parameters = new JAdESSignatureParameters();
        parameters.setSignatureLevel(SignatureLevel.JAdES_BASELINE_B);
        parameters.setSignaturePackaging(SignaturePackaging.ENVELOPING);
        parameters.setJwsSerializationType(JWSSerializationType.JSON_SERIALIZATION);
        parameters.setDigestAlgorithm(DigestAlgorithm.SHA256);
        // iat incondicional (independente do resultado B-B/B-T) — ETSI TS 119 182-1 §5.1.11
        parameters.setJadesSigningTimeType(JAdESSigningTimeType.IAT);
        parameters.bLevel().setSigningDate(Date.from(Instant.ofEpochSecond(request.referenceTimestamp())));

        parameters.setIncludeCertificateChain(true);
        parameters.setIncludeSignatureType(false);
        parameters.setIncludeKeyIdentifier(false);
        // DIVERGENCIA-IG D1: x5t#S256 exigido pelo JAdES-B-B (§6.3); o header fechado do IG 0.2.0 o omite
        parameters.setSigningCertificateDigestMethod(DigestAlgorithm.SHA256);
        parameters.setSigningCertificate(new CertificateToken(signer));
        parameters.setCertificateChain(request.certificateChain().stream()
                .map(CertificateToken::new)
                .toList());

        Policy policy = new Policy();
        policy.setId(request.policyId());
        parameters.bLevel().setSignaturePolicy(policy);
        parameters.bLevel().setCommitmentTypeIndications(List.of(verificationSignature()));

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
     * Monta o JWS General JSON Serialization com o valor RSASSA-PKCS1-v1_5/SHA-256 produzido
     * externamente sobre {@link #dataToSign(JadesSigningSession)}.
     *
     * @return JWS em General JSON Serialization (JSON compacto)
     */
    public String sign(JadesSigningSession session, byte[] signatureValue) {
        SignatureValue value = new SignatureValue(SignatureAlgorithm.RSA_SHA256, signatureValue);
        DSSDocument signed = newService().signDocument(document(session), session.parameters(), value);
        return new String(DSSUtils.toByteArray(signed), StandardCharsets.UTF_8);
    }

    private static CommonCommitmentType verificationSignature() {
        CommonCommitmentType commitment = new CommonCommitmentType();
        commitment.setOid(VERIFICATION_SIGNATURE_OID);
        // srCms[0].commId.id = "urn:oid:1.2.840.10065.1.12.1.5"
        commitment.setQualifier(ObjectIdentifierQualifier.OID_AS_URN);
        return commitment;
    }

    private JAdESService newService() {
        // Assinatura B-B não consulta fontes externas: verifier vazio é suficiente.
        return new JAdESService(new CommonCertificateVerifier());
    }

    private DSSDocument document(JadesSigningSession session) {
        return new InMemoryDocument(session.payload());
    }
}
