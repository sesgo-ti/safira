/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.steps.signing.ContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningInputStep;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Passo {@code jades-data-to-sign} (política 2.0.0): monta os parâmetros JAdES-B-B via EU DSS
 * e publica o <em>signing input</em> para o passo {@code crypto-signing}.
 *
 * <p>Lê do contexto: cadeia de certificados, {@code referenceTimestamp}, URI da política e o
 * atributo {@code contentDigest} (payload attached — requisito C15 do IG SES-GO).
 * Escreve: {@code jadesSession} (sessão DSS congelada) e {@code signingInputBytes}
 * (mesma chave consumida pelo {@code crypto-signing} da política legada — reuso integral).
 */
@StepId("jades-data-to-sign")
public class JadesDataToSignStep implements SigningStep {

    public static final String JADES_SESSION_KEY = "jadesSession";

    private final JadesSigningService signingService;

    public JadesDataToSignStep() {
        this(new JadesSigningService());
    }

    public JadesDataToSignStep(JadesSigningService signingService) {
        this.signingService = signingService;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        X509Certificate[] chain = context.getCertificateChain()
                .orElse(null);
        if (chain == null || chain.length == 0) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                    "Cadeia de certificados ausente no contexto. Verifique se o step chain-build foi executado.",
                    context);
        }

        String contentDigest = context
                .getAttribute(ContentDigestStep.CONTENT_DIGEST_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED,
                        "A impressão digital do conteúdo não foi encontrada no contexto. "
                                + "Verifique se o step content-digest foi executado."));

        try {
            byte[] payload = Base64.getUrlDecoder().decode(contentDigest);

            JadesSigningSession session = signingService.newSession(new JadesSigningService.Request(
                    List.of(chain),
                    payload,
                    context.getReferenceTimestamp(),
                    context.getPolicyIdentifierUri(),
                    null,
                    null));

            byte[] dataToSign = signingService.dataToSign(session);

            SigningContext updated = context.toBuilder()
                    .attribute(JADES_SESSION_KEY, session)
                    .attribute(SigningInputStep.SIGNING_INPUT_BYTES_KEY, dataToSign)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (IllegalArgumentException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Impressão digital do conteúdo não é base64url válido: " + e.getMessage(), context);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao preparar os dados a assinar (JAdES): " + e.getMessage(), e);
        }
    }
}
