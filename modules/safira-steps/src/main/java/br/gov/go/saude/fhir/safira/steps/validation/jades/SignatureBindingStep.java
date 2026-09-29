/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import br.gov.go.saude.fhir.safira.steps.content.Base64Strict;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Passo {@code signature-binding}: seções 1 e 3.1 (parcial) do caso de uso de validação —
 * metadados da {@code Signature} FHIR, extração estrita de {@code Signature.data}, igualdade
 * integral com o único {@code Provenance.signature} e correspondência com {@code Provenance.agent}.
 * Escreve {@link ValidationKeys#JWS_JSON}.
 */
@StepId("signature-binding")
public class SignatureBindingStep implements ValidationStep {

    private static final Set<String> IDENTITY_SYSTEMS = Set.of(SignerIdentity.CPF_SYSTEM, SignerIdentity.CNPJ_SYSTEM);

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        JsonObject signature = context.getSignatureJson();

        if (!Policy020.SIG_FORMAT.equals(signature.string("sigFormat").orElse(null))
                || !Policy020.TARGET_FORMAT.equals(signature.string("targetFormat").orElse(null))) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Signature.sigFormat deve ser application/jose+json e Signature.targetFormat application/fhir+json.", context);
        }
        if (!hasVerificationSignatureType(signature)) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Signature.type deve conter exatamente Verification Signature (urn:iso-astm:E1762-95:2013#1.2.840.10065.1.12.1.5).",
                    context);
        }
        Optional<JsonObject> identifier = signature.object("who").flatMap(who -> who.object("identifier"));
        if (identifier.isEmpty() || !IDENTITY_SYSTEMS.contains(identifier.get().string("system").orElse(""))
                || identifier.get().string("value").isEmpty() || signature.string("when").isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_PROFILE_VALIDATION_FAILED,
                    "Signature.when e Signature.who.identifier (urn:brasil:cpf | urn:brasil:cnpj) são obrigatórios.", context);
        }

        Optional<String> jws = signature.string("data").flatMap(Base64Strict::standard).flatMap(SignatureBindingStep::utf8);
        if (jws.isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Signature.data deve ser Base64 padrão canônico de bytes UTF-8 (sem BOM).", context);
        }

        List<JsonValue> provenanceSignatures = context.getProvenanceJson().array("signature")
                .map(JsonArray::items).orElse(List.of());
        if (provenanceSignatures.isEmpty()) {
            return fail(SignatureExceptionCode.FORMAT_SIGNATURE_MISSING, "Provenance.signature está ausente.", context);
        }
        if (provenanceSignatures.size() > 1) {
            return fail(SignatureExceptionCode.FORMAT_PROVENANCE_INVALID,
                    "Provenance.signature deve conter exatamente uma assinatura.", context);
        }
        if (!signature.equals(provenanceSignatures.getFirst())) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Provenance.signature difere da Signature informada na entrada 1.", context);
        }
        if (!hasMatchingAgent(context.getProvenanceJson(), identifier.get())) {
            return fail(SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Nenhum Provenance.agent.who.identifier é integralmente igual a Signature.who.identifier.", context);
        }
        return StepResult.success(getName(), context.toBuilder().attribute(ValidationKeys.JWS_JSON, jws.get()).build());
    }

    private static boolean hasVerificationSignatureType(JsonObject signature) {
        List<JsonValue> types = signature.array("type").map(JsonArray::items).orElse(List.of());
        if (types.size() != 1 || !(types.getFirst() instanceof JsonObject coding)) {
            return false;
        }
        return Policy020.SIGNATURE_TYPE_SYSTEM.equals(coding.string("system").orElse(null))
                && Policy020.VERIFICATION_SIGNATURE_OID.equals(coding.string("code").orElse(null));
    }

    private static boolean hasMatchingAgent(JsonObject provenance, JsonObject identifier) {
        return provenance.array("agent").map(JsonArray::items).orElse(List.of()).stream()
                .filter(JsonObject.class::isInstance)
                .map(JsonObject.class::cast)
                .flatMap(agent -> agent.object("who").stream())
                .flatMap(who -> who.object("identifier").stream())
                .anyMatch(identifier::equals);
    }

    private static Optional<String> utf8(byte[] bytes) {
        if (bytes.length >= 3 && (bytes[0] & 0xFF) == 0xEF && (bytes[1] & 0xFF) == 0xBB && (bytes[2] & 0xFF) == 0xBF) {
            return Optional.empty();
        }
        try {
            return Optional.of(StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(bytes)).toString());
        } catch (CharacterCodingException e) {
            return Optional.empty();
        }
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
