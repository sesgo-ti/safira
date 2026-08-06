/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

/**
 * Step: monta a estrutura preliminar do JWS (passo 11 da especificação).
 *
 * <p>Constrói o objeto JSON JWS (General JSON Serialization, RFC 7515 §7.2.1) contendo
 * apenas {@code payload}, {@code signatures[].protected} e {@code signatures[].signature}.
 * O unprotected header ({@code signatures[].header}) é adicionado pelo {@code JwsFinalStep}.
 *
 * <p>O resultado é armazenado como {@link ObjectNode} mutável (não serializado) para permitir
 * que o step final adicione o unprotected header sem precisar desserializar novamente.
 */
@StepId("jws-preliminary")
public class JwsPreliminaryStep implements SigningStep {

    public static final String JWS_PRELIMINARY_KEY = "jwsPreliminary";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        String protectedHeader = context
                .getAttribute(ProtectedHeaderStep.PROTECTED_HEADER_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O protected header não foi encontrado no contexto."));

        String payload = context
                .getAttribute(ContentDigestStep.CONTENT_DIGEST_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "O content digest (payload) não foi encontrado no contexto."));

        String signature = context
                .getAttribute(CryptoSigningStep.SIGNATURE_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "A assinatura criptográfica não foi encontrada no contexto."));

        ObjectNode jws = MAPPER.createObjectNode();
        jws.put("payload", payload);

        ArrayNode signatures = jws.putArray("signatures");
        ObjectNode signatureEntry = signatures.addObject();
        signatureEntry.put("protected", protectedHeader);
        signatureEntry.put("signature", signature);

        SigningContext updated = context.toBuilder()
                .attribute(JWS_PRELIMINARY_KEY, jws)
                .build();

        return StepResult.success(getName(), updated);
    }
}
