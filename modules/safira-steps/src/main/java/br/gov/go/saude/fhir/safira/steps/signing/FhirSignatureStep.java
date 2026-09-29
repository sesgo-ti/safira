/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonArray;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonObject;
import br.gov.go.saude.fhir.safira.engine.domain.json.JsonValue.JsonString;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.certificate.SignerIdentity;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Passo {@code fhir-signature}: etapa 14 do caso de uso de criação (C13, C14).
 *
 * <p>Encapsula o JWS em uma {@code Signature} FHIR — {@code type} Verification Signature,
 * {@code when} = {@code iat}, {@code who.identifier} CPF/CNPJ do certificado,
 * {@code targetFormat} {@code application/fhir+json}, {@code sigFormat}
 * {@code application/jose+json} e {@code data} = Base64 padrão dos bytes UTF-8 do JWS — e cria
 * uma cópia do Provenance recebido com exatamente essa assinatura em {@code Provenance.signature},
 * sem mutar a entrada. Exige um {@code Provenance.agent} cujo {@code who.identifier} seja
 * integralmente igual a {@code Signature.who.identifier}.
 */
@StepId("fhir-signature")
public class FhirSignatureStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        String jws = context.getAttribute(SigningKeys.JWS_FINAL, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A estrutura JWS final não foi encontrada no contexto."));
        SignerIdentity signer = context.getAttribute(CertificatePolicyStep.SIGNER_IDENTITY_KEY, SignerIdentity.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CERT_MISSING_IDENTIFICATION,
                        "Identidade do signatário ausente; o step certificate-policy deve precedê-lo."));

        JsonObject identifier = object("system", new JsonString(signer.system()),
                "value", new JsonString(signer.value()));
        JsonObject who = object("identifier", identifier);

        if (!hasMatchingAgent(context.getProvenanceJson(), identifier)) {
            return StepResult.failure(getName(), SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED,
                    "Nenhum Provenance.agent.who.identifier é integralmente igual à identidade do signatário ("
                            + signer.system() + ").", context);
        }

        JsonObject signature = object(
                "type", new JsonArray(List.of(object(
                        "system", new JsonString(Policy020.SIGNATURE_TYPE_SYSTEM),
                        "code", new JsonString(Policy020.VERIFICATION_SIGNATURE_OID)))),
                "when", new JsonString(Instant.ofEpochSecond(context.getReferenceTimestamp()).toString()),
                "who", who,
                "targetFormat", new JsonString(Policy020.TARGET_FORMAT),
                "sigFormat", new JsonString(Policy020.SIG_FORMAT),
                "data", new JsonString(Base64.getEncoder().encodeToString(jws.getBytes(StandardCharsets.UTF_8))));

        JsonObject provenanceCopy = context.getProvenanceJson().with("signature", new JsonArray(List.of(signature)));

        return StepResult.success(getName(), context.toBuilder()
                .signingResult(new SigningResult(LosslessJson.write(signature), LosslessJson.write(provenanceCopy)))
                .build());
    }

    private static boolean hasMatchingAgent(JsonObject provenance, JsonObject identifier) {
        return provenance.array("agent").map(JsonArray::items).orElse(List.of()).stream()
                .filter(JsonObject.class::isInstance)
                .map(JsonObject.class::cast)
                .flatMap(agent -> agent.object("who").stream())
                .flatMap(who -> who.object("identifier").stream())
                .anyMatch(identifier::equals);
    }

    /** Objeto com os pares nome/valor na ordem informada. */
    private static JsonObject object(Object... pairs) {
        Map<String, JsonValue> members = new LinkedHashMap<>();
        for (int i = 0; i < pairs.length; i += 2) {
            members.put((String) pairs[i], (JsonValue) pairs[i + 1]);
        }
        return new JsonObject(members);
    }
}
