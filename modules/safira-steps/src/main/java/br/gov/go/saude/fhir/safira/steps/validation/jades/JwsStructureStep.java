/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonNumber;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJsonException;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.content.Base64Strict;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Passo {@code jws-structure}: seção 2 do caso de uso de validação — parsing estrito do General
 * JWS JSON, payload attached de 32 bytes, protected header fechado da política 0.2.0 e
 * identificação exata do nível local (JAdES-B-B ou JAdES-B-T).
 *
 * <p>Escreve {@code certificateChain} ({@code x5c}) e os atributos {@link ValidationKeys#JADES_LEVEL},
 * {@link ValidationKeys#IAT}, {@link ValidationKeys#PAYLOAD} e {@link ValidationKeys#SIGNATURE_TEXT}.
 */
@StepId("jws-structure")
public class JwsStructureStep implements ValidationStep {

    // DIVERGENCIA-IG D1: x5t#S256 acrescentado ao header fechado do IG 0.2.0 (conformidade JAdES-B-B)
    private static final Set<String> PROTECTED_MEMBERS = Set.of("alg", "x5t#S256", "x5c", "iat", "sigPId", "srCms");
    private static final Set<String> JADES_UNPROTECTED_COMPONENTS = Set.of(
            "sigD", "sigTst", "etsiU", "rRefs", "xRefs", "rVals", "xVals", "arcTst", "tstVD", "sigT");
    private static final String SIG_P_ID = "{\"id\":{\"id\":\"" + Policy020.POLICY_URI + "\"}}";
    private static final String SR_CMS = "[{\"commId\":{\"id\":\"urn:oid:" + Policy020.VERIFICATION_SIGNATURE_OID + "\"}}]";

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        String jws = context.getAttribute(ValidationKeys.JWS_JSON, String.class).orElse(null);
        try {
            return validate(jws, context);
        } catch (LosslessJsonException e) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "JWS JSON inválido ou com membros duplicados: " + e.getMessage(), context);
        }
    }

    private StepResult<ValidationContext> validate(String jws, ValidationContext context) {
        if (!(LosslessJson.parse(jws) instanceof JsonObject root) || !root.names().equals(Set.of("payload", "signatures"))) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "O JWS deve ser General JSON Serialization com exatamente 'payload' e 'signatures'.", context);
        }
        List<JsonValue> signatures = root.array("signatures").map(JsonArray::items).orElse(List.of());
        if (signatures.size() != 1 || !(signatures.getFirst() instanceof JsonObject signature)) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED, "'signatures' deve conter exatamente um objeto.", context);
        }
        Set<String> members = signature.names();
        if (!members.contains("protected") || !members.contains("signature")
                || !Set.of("protected", "signature", "header").containsAll(members)) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "O objeto de assinatura deve conter 'protected' e 'signature' e, no máximo, 'header'.", context);
        }
        Optional<byte[]> payload = root.string("payload").flatMap(Base64Strict::urlNoPadding);
        if (payload.isEmpty() || payload.get().length != 32) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "'payload' deve ser Base64URL canônico, sem padding, de exatamente 32 bytes (SHA-256).", context);
        }
        Optional<byte[]> headerBytes = signature.string("protected").flatMap(Base64Strict::urlNoPadding);
        if (headerBytes.isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED, "'protected' deve ser Base64URL canônico sem padding.", context);
        }
        JsonObject header = LosslessJson.parseObject(new String(headerBytes.get(), StandardCharsets.UTF_8));

        StepResult<ValidationContext> headerFailure = checkProtectedHeader(header, context);
        if (headerFailure != null) {
            return headerFailure;
        }
        List<X509Certificate> x5c = new ArrayList<>();
        StepResult<ValidationContext> chainFailure = decodeChain(header, x5c, context);
        if (chainFailure != null) {
            return chainFailure;
        }

        JadesLevel level;
        if (signature.get("header").isEmpty()) {
            level = JadesLevel.B_B;
        } else if (isLocalBaselineTHeader(signature.get("header").get())) {
            level = JadesLevel.B_T;
        } else {
            return fail(SignatureExceptionCode.FORMAT_JADES_UNPROTECTED_HEADER_INVALID,
                    "'header' deve ser {\"etsiU\":[{\"sigTst\":{\"tstTokens\":[{\"val\":...}]}}]} em representação clara.",
                    context);
        }

        String signatureText = signature.string("signature").orElse("");
        Optional<byte[]> signatureValue = Base64Strict.urlNoPadding(signatureText);
        if (signatureValue.isEmpty() || (signatureValue.get().length != 256 && signatureValue.get().length != 512)) {
            return fail(SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED,
                    "'signature' deve ser Base64URL canônico de 256 (RSA-2048) ou 512 (RSA-4096) bytes.", context);
        }

        long iat = Long.parseLong(((JsonNumber) header.get("iat").orElseThrow()).lexical());
        return StepResult.success(getName(), context.toBuilder()
                .certificateChain(List.copyOf(x5c))
                .attribute(ValidationKeys.JADES_LEVEL, level)
                .attribute(ValidationKeys.IAT, iat)
                .attribute(ValidationKeys.PAYLOAD, payload.get())
                .attribute(ValidationKeys.SIGNATURE_TEXT, signatureText)
                .build());
    }

    private StepResult<ValidationContext> checkProtectedHeader(JsonObject header, ValidationContext context) {
        for (String name : header.names()) {
            if (JADES_UNPROTECTED_COMPONENTS.contains(name)) {
                return fail(SignatureExceptionCode.FORMAT_JADES_COMPONENT_PLACEMENT_INVALID,
                        "Componente JAdES '" + name + "' não é permitido no protected header.", context);
            }
            if (!PROTECTED_MEMBERS.contains(name)) {
                return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                        "Membro '" + name + "' não é permitido no protected header da política 0.2.0.", context);
            }
        }
        if (header.get("iat").isEmpty()) {
            return fail(SignatureExceptionCode.TEMPORAL_IAT_MISSING, "O protected header não contém 'iat'.", context);
        }
        if (!header.names().containsAll(PROTECTED_MEMBERS)) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "O protected header deve conter exatamente " + PROTECTED_MEMBERS + ".", context);
        }
        if (!Policy020.JWS_ALGORITHM.equals(header.string("alg").orElse(null))) {
            return fail(SignatureExceptionCode.VALIDATION_UNSUPPORTED_ALGORITHM, "'alg' deve ser RS256.", context);
        }
        if (!(header.get("iat").get() instanceof JsonNumber iat) || !iat.lexical().matches("[1-9]\\d{0,18}")) {
            return fail(SignatureExceptionCode.TEMPORAL_IAT_INVALID,
                    "'iat' deve ser NumericDate inteiro positivo, sem fração nem expoente.", context);
        }
        if (!SIG_P_ID.equals(LosslessJson.write(header.get("sigPId").get()))) {
            return fail(SignatureExceptionCode.POLICY_SIGNATURE_POLICY_ID_INVALID,
                    "'sigPId' deve ser exatamente " + SIG_P_ID + ".", context);
        }
        if (!SR_CMS.equals(LosslessJson.write(header.get("srCms").get()))) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "'srCms' deve ser exatamente " + SR_CMS + ".", context);
        }
        return null;
    }

    private StepResult<ValidationContext> decodeChain(JsonObject header, List<X509Certificate> out, ValidationContext context) {
        List<JsonValue> items = header.array("x5c").map(JsonArray::items).orElse(List.of());
        if (items.isEmpty()) {
            return fail(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE, "'x5c' deve ser um array não vazio.", context);
        }
        Set<String> seen = new HashSet<>();
        for (int i = 0; i < items.size(); i++) {
            Optional<byte[]> der = items.get(i) instanceof JsonString s ? Base64Strict.standard(s.value()) : Optional.empty();
            X509Certificate certificate = der.map(JwsStructureStep::certificate).orElse(null);
            if (certificate == null) {
                return fail(SignatureExceptionCode.CERT_INVALID_FORMAT,
                        "x5c[" + i + "] não é Base64 padrão canônico de exatamente um certificado X.509 DER.", context);
            }
            if (!seen.add(((JsonString) items.get(i)).value())) {
                return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED, "'x5c' contém certificados duplicados.", context);
            }
            if (i > 0 && !out.get(i - 1).getIssuerX500Principal().equals(certificate.getSubjectX500Principal())) {
                return fail(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                        "x5c[" + i + "] não é o emissor de x5c[" + (i - 1) + "].", context);
            }
            // O issuerSha256 da allowlist é calculado sobre x5c[1]: o encadeamento exige assinatura, não só nome
            if (i > 0 && !signedBy(out.get(i - 1), certificate)) {
                return fail(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED,
                        "A assinatura de x5c[" + (i - 1) + "] não confere com a chave de x5c[" + i + "].", context);
            }
            out.add(certificate);
        }
        String thumbprint = header.string("x5t#S256").orElse("");
        if (!thumbprint.equals(sha256Base64Url(out.getFirst()))) {
            return fail(SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "'x5t#S256' não corresponde ao SHA-256 do certificado x5c[0].", context);
        }
        return null;
    }

    private static boolean isLocalBaselineTHeader(JsonValue header) {
        if (!(header instanceof JsonObject object) || !object.names().equals(Set.of("etsiU"))) {
            return false;
        }
        List<JsonValue> etsiU = object.array("etsiU").map(JsonArray::items).orElse(List.of());
        if (etsiU.size() != 1 || !(etsiU.getFirst() instanceof JsonObject component)
                || !component.names().equals(Set.of("sigTst"))) {
            return false;
        }
        Optional<JsonObject> sigTst = component.object("sigTst");
        if (sigTst.isEmpty() || !sigTst.get().names().equals(Set.of("tstTokens"))) {
            return false;
        }
        List<JsonValue> tokens = sigTst.get().array("tstTokens").map(JsonArray::items).orElse(List.of());
        return tokens.size() == 1 && tokens.getFirst() instanceof JsonObject token
                && token.names().equals(Set.of("val")) && token.string("val").isPresent();
    }

    private static X509Certificate certificate(byte[] der) {
        try {
            X509Certificate certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(new ByteArrayInputStream(der));
            return MessageDigest.isEqual(certificate.getEncoded(), der) ? certificate : null;
        } catch (CertificateException | ClassCastException e) {
            return null;
        }
    }

    private static boolean signedBy(X509Certificate certificate, X509Certificate issuer) {
        try {
            certificate.verify(issuer.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static String sha256Base64Url(X509Certificate certificate) {
        try {
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.getEncoded()));
        } catch (NoSuchAlgorithmException | CertificateException e) {
            throw new IllegalStateException(e);
        }
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
