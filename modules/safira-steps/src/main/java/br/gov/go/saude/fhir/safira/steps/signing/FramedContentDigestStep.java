/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.steps.content.FramedContentDigest;
import br.gov.go.saude.fhir.safira.steps.content.SignedContentRules;

import java.util.Base64;

/**
 * Passo {@code framed-content-digest}: etapas 3 a 6 do caso de uso de criação — remoção dos
 * elementos não assinados, canonicalização {@code fhir-json-lossless/0.2.0}, artefato enquadrado
 * {@code UINT64_BE} e SHA-256 codificado em base64url sem padding (payload attached, 43
 * caracteres). Escreve o atributo {@link SigningKeys#CONTENT_DIGEST}.
 */
@StepId("framed-content-digest")
public class FramedContentDigestStep implements SigningStep {

    @Override
    public StepResult<SigningContext> execute(SigningContext context) {
        try {
            byte[] digest = FramedContentDigest.sha256(
                    SignedContentRules.orderedParts(context.getBundleJson(), context.getProvenanceJson()));
            return StepResult.success(getName(), context.toBuilder()
                    .attribute(SigningKeys.CONTENT_DIGEST,
                            Base64.getUrlEncoder().withoutPadding().encodeToString(digest))
                    .build());
        } catch (RuntimeException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_CANONICALIZATION_FAILED,
                    "Falha na canonicalização lossless do conteúdo assinado: " + e.getMessage(), context);
        }
    }
}
