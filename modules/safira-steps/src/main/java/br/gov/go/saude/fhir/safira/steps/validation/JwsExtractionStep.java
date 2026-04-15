package br.gov.go.saude.fhir.safira.steps.validation;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@StepId("jws-extraction")
public class JwsExtractionStep implements ValidationStep {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        String signedDataBase64 = context.getSignedDataBase64();

        byte[] jwsJsonBytes;
        try {
            jwsJsonBytes = Base64.getDecoder().decode(signedDataBase64 == null ? "" : signedDataBase64);
        } catch (IllegalArgumentException ex) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Conteúdo assinado não está em Base64 válido.", context);
        }

        String rawJwsJson = new String(jwsJsonBytes, StandardCharsets.UTF_8);

        JsonNode root;
        try {
            root = MAPPER.readTree(rawJwsJson);
        } catch (Exception ex) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "JSON do JWS malformado.", context);
        }

        if (root == null || !root.isObject()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Estrutura JWS não é um objeto JSON.", context);
        }

        JsonNode payloadNode = root.get("payload");
        if (payloadNode == null || !payloadNode.isTextual()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Campo 'payload' ausente ou inválido no JWS.", context);
        }

        JsonNode signaturesNode = root.get("signatures");
        if (signaturesNode == null || !signaturesNode.isArray()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Campo 'signatures' ausente ou não é um array.", context);
        }
        if (signaturesNode.isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Array 'signatures' está vazio.", context);
        }

        JsonNode first = signaturesNode.get(0);
        if (first == null || !first.isObject()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Primeira entrada de 'signatures' não é um objeto.", context);
        }

        JsonNode protectedNode = first.get("protected");
        if (protectedNode == null || !protectedNode.isTextual()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Campo 'protected' ausente na assinatura.", context);
        }

        JsonNode signatureValueNode = first.get("signature");
        if (signatureValueNode == null || !signatureValueNode.isTextual()) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Campo 'signature' ausente na assinatura.", context);
        }

        String rawProtectedBase64Url = protectedNode.asText();

        byte[] decodedProtected;
        try {
            decodedProtected = Base64.getUrlDecoder().decode(rawProtectedBase64Url);
        } catch (IllegalArgumentException ex) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Protected header não está em Base64URL válido.", context);
        }

        Map<String, Object> protectedHeader;
        try {
            JsonNode protectedParsed = MAPPER.readTree(decodedProtected);
            if (protectedParsed == null || !protectedParsed.isObject()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                        "Protected header não é um objeto JSON.", context);
            }
            protectedHeader = MAPPER.convertValue(protectedParsed, MAP_TYPE);
        } catch (Exception ex) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                    "Protected header inválido: " + ex.getMessage(), context);
        }

        Map<String, Object> unprotectedHeader = null;
        JsonNode headerNode = first.get("header");
        if (headerNode != null && !headerNode.isNull()) {
            if (!headerNode.isObject()) {
                return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_JWS_MALFORMED,
                        "Campo 'header' (unprotected) deve ser um objeto.", context);
            }
            unprotectedHeader = MAPPER.convertValue(headerNode, MAP_TYPE);
        }

        byte[] signatureBytes;
        try {
            signatureBytes = Base64.getUrlDecoder().decode(signatureValueNode.asText());
        } catch (IllegalArgumentException ex) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Assinatura não está em Base64URL válido.", context);
        }

        ValidationContext updated = context.toBuilder()
                .rawJwsJson(rawJwsJson)
                .payloadBase64Url(payloadNode.asText())
                .rawProtectedHeaderBase64Url(rawProtectedBase64Url)
                .protectedHeader(protectedHeader)
                .unprotectedHeader(unprotectedHeader)
                .signatureBytes(signatureBytes)
                .build();

        return StepResult.success(getName(), updated);
    }
}
