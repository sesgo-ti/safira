/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.timestamp;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.tsp.Accuracy;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.tsp.TimeStampTokenInfo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Inspeção e verificação de um {@code TimeStampToken} RFC 3161 segundo a política 0.2.0
 * (criar 12.3; validar 5.1–5.4). A cadeia do certificado TSA e sua revogação são verificadas
 * por quem chama, contra o trust store TSA da política selecionada.
 */
public final class TimestampTokenInspector {

    /**
     * @param policyOid         {@code TSTInfo.policy}
     * @param genTime           {@code TSTInfo.genTime}
     * @param accuracyMicros    {@code TSTInfo.accuracy} em microssegundos; nulo se ausente
     * @param tsaCertificate    certificado identificado por {@code SignerInfo.sid}
     * @param tokenCertificates certificados transportados pelo token (candidatos de cadeia)
     * @param token             token decodificado
     */
    public record Inspection(String policyOid, Instant genTime, Long accuracyMicros,
                             X509Certificate tsaCertificate, List<X509Certificate> tokenCertificates,
                             TimeStampToken token) {

        /** Accuracy arredondada para cima, em segundos; nulo se ausente. */
        public Long accuracySeconds() {
            return accuracyMicros == null ? null : (accuracyMicros + 999_999) / 1_000_000;
        }
    }

    private TimestampTokenInspector() {
    }

    public static Inspection inspect(byte[] timeStampTokenDer) {
        try {
            TimeStampToken token = new TimeStampToken(new CMSSignedData(timeStampTokenDer));
            TimeStampTokenInfo info = token.getTimeStampInfo();
            JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
            List<X509Certificate> certificates = new ArrayList<>();
            X509Certificate tsa = null;
            Collection<X509CertificateHolder> holders = token.getCertificates().getMatches(null);
            for (X509CertificateHolder holder : holders) {
                X509Certificate certificate = converter.getCertificate(holder);
                certificates.add(certificate);
                if (token.getSID().match(holder)) {
                    tsa = certificate;
                }
            }
            if (tsa == null) {
                throw new TimestampTokenException(SignatureExceptionCode.TSA_INVALID_TOKEN,
                        "O TimeStampToken não transporta o certificado da TSA (certReq=true é obrigatório).");
            }
            return new Inspection(info.getPolicy().getId(), info.getGenTime().toInstant(),
                    accuracyMicros(info.getAccuracy()), tsa, List.copyOf(certificates), token);
        } catch (TimestampTokenException e) {
            throw e;
        } catch (Exception e) {
            throw new TimestampTokenException(SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "TimeStampToken malformado (CMS/TSTInfo): " + e.getMessage(), e);
        }
    }

    /** Token em {@code signatures[0].header.etsiU[0].sigTst.tstTokens[0].val} (Base64 padrão). */
    public static byte[] tokenFromJws(String jwsJson) {
        String val = LosslessJson.parseObject(jwsJson).array("signatures")
                .flatMap(a -> first(a).filter(JsonObject.class::isInstance).map(JsonObject.class::cast))
                .flatMap(s -> s.object("header"))
                .flatMap(h -> h.array("etsiU"))
                .flatMap(a -> first(a).filter(JsonObject.class::isInstance).map(JsonObject.class::cast))
                .flatMap(e -> e.object("sigTst"))
                .flatMap(t -> t.array("tstTokens"))
                .flatMap(a -> first(a).filter(JsonObject.class::isInstance).map(JsonObject.class::cast))
                .flatMap(t -> t.string("val"))
                .orElseThrow(() -> new TimestampTokenException(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID,
                        "JWS sem header.etsiU[0].sigTst.tstTokens[0].val."));
        try {
            byte[] der = Base64.getDecoder().decode(val);
            if (!Base64.getEncoder().encodeToString(der).equals(val)) {
                throw new IllegalArgumentException("representação Base64 não canônica");
            }
            return der;
        } catch (IllegalArgumentException e) {
            throw new TimestampTokenException(SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "sigTst.tstTokens[0].val não é Base64 padrão canônico: " + e.getMessage(), e);
        }
    }

    /**
     * @param inspection    token inspecionado
     * @param signatureText texto exato de {@code signatures[0].signature}
     * @param iat           {@code iat} protegido (epoch seconds)
     * @param policy        política TSA selecionada pelo OID do token
     * @param signerChain   cadeia ICP-Brasil do signatário (folha primeiro)
     * @param upperBound    limite superior admitido para o intervalo (validação: timestamp de
     *                      referência; criação: {@link Long#MAX_VALUE})
     */
    public static Optional<PolicyViolation> verify(Inspection inspection, String signatureText, long iat,
                                                   TsaPolicy policy, List<X509Certificate> signerChain,
                                                   long upperBound) {
        if (!policy.oid().equals(inspection.policyOid())) {
            return fail(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                    "Política do carimbo " + inspection.policyOid() + " difere da política TSA aceita " + policy.oid() + ".");
        }
        if (!imprintMatches(inspection.token().getTimeStampInfo(), signatureText)) {
            return fail(SignatureExceptionCode.TSA_MESSAGE_IMPRINT_MISMATCH,
                    "O messageImprint não é o SHA-256 do texto ASCII de signatures[0].signature.");
        }
        if (!hasExclusiveCriticalTimestampingEku(inspection.tsaCertificate())) {
            return fail(SignatureExceptionCode.TSA_CERTIFICATE_PURPOSE_INVALID,
                    "O certificado da TSA deve ter EKU crítico exclusivamente id-kp-timeStamping.");
        }
        long maxMicros = policy.maxAccuracySeconds() * 1_000_000;
        if (inspection.accuracyMicros() != null && inspection.accuracyMicros() > maxMicros) {
            return fail(SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "accuracy do carimbo excede maxAccuracySeconds da política TSA.");
        }
        long accuracyMicros = inspection.accuracyMicros() == null ? maxMicros : inspection.accuracyMicros();
        long genMicros = inspection.genTime().getEpochSecond() * 1_000_000 + inspection.genTime().getNano() / 1_000;
        long lower = genMicros - accuracyMicros;
        long upper = genMicros + accuracyMicros;
        long tolerance = Policy020.CLOCK_TOLERANCE_SECONDS * 1_000_000;
        if (lower < iat * 1_000_000 - tolerance || upper > iat * 1_000_000 + tolerance) {
            return fail(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS,
                    "O intervalo do carimbo não está contido em [iat - 300 s, iat + 300 s].");
        }
        if (upperBound != Long.MAX_VALUE && upper > upperBound * 1_000_000) {
            return fail(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS,
                    "O limite superior do intervalo do carimbo é posterior ao timestamp de referência.");
        }
        for (X509Certificate certificate : signerChain) {
            if (!covers(certificate, lower, upper)) {
                return fail(SignatureExceptionCode.TEMPORAL_TSA_TIMESTAMP_OUT_OF_BOUNDS,
                        "O intervalo do carimbo não está contido na validade de "
                                + certificate.getSubjectX500Principal().getName() + ".");
            }
        }
        if (!covers(inspection.tsaCertificate(), lower, upper)) {
            return fail(SignatureExceptionCode.TSA_CERTIFICATE_TIME_INVALID,
                    "O intervalo do carimbo não está contido na validade do certificado da TSA.");
        }
        // Após as checagens temporais: o validate() do BC também rejeita certificado fora da validade
        try {
            // Verifica assinatura CMS, atributos assinados e ESSCertID/ESSCertIDv2 contra o certificado da TSA
            inspection.token().validate(new JcaSimpleSignerInfoVerifierBuilder().build(inspection.tsaCertificate()));
        } catch (Exception e) {
            return fail(SignatureExceptionCode.TSA_SIGNATURE_INVALID, "Assinatura CMS do carimbo inválida: " + e.getMessage());
        }
        return Optional.empty();
    }

    private static boolean imprintMatches(TimeStampTokenInfo info, String signatureText) {
        if (!NISTObjectIdentifiers.id_sha256.equals(info.getMessageImprintAlgOID())) {
            return false;
        }
        try {
            byte[] expected = MessageDigest.getInstance("SHA-256")
                    .digest(signatureText.getBytes(StandardCharsets.US_ASCII));
            return MessageDigest.isEqual(expected, info.getMessageImprintDigest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 indisponível", e);
        }
    }

    private static boolean hasExclusiveCriticalTimestampingEku(X509Certificate certificate) {
        if (!certificate.getCriticalExtensionOIDs().contains(Extension.extendedKeyUsage.getId())) {
            return false;
        }
        try {
            ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(
                    new X509CertificateHolder(certificate.getEncoded()).getExtension(Extension.extendedKeyUsage).getParsedValue());
            KeyPurposeId[] usages = eku.getUsages();
            return usages.length == 1 && KeyPurposeId.id_kp_timeStamping.equals(usages[0]);
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean covers(X509Certificate certificate, long lowerMicros, long upperMicros) {
        long notBefore = certificate.getNotBefore().toInstant().getEpochSecond() * 1_000_000;
        long notAfter = certificate.getNotAfter().toInstant().getEpochSecond() * 1_000_000;
        return lowerMicros >= notBefore && upperMicros <= notAfter;
    }

    private static Long accuracyMicros(Accuracy accuracy) {
        if (accuracy == null) {
            return null;
        }
        long seconds = accuracy.getSeconds() == null ? 0 : accuracy.getSeconds().longValueExact();
        long millis = accuracy.getMillis() == null ? 0 : accuracy.getMillis().longValueExact();
        long micros = accuracy.getMicros() == null ? 0 : accuracy.getMicros().longValueExact();
        return seconds * 1_000_000 + millis * 1_000 + micros;
    }

    private static Optional<JsonValue> first(JsonArray array) {
        return array.items().isEmpty() ? Optional.empty() : Optional.of(array.items().getFirst());
    }

    private static Optional<PolicyViolation> fail(SignatureExceptionCode code, String diagnostics) {
        return Optional.of(new PolicyViolation(code, diagnostics));
    }
}
