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
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.List;

/**
 * Passo {@code jades-data-to-sign}: monta os parâmetros JAdES-B-B via EU DSS e publica o
 * <em>signing input</em> para o passo {@code crypto-signing}.
 *
 * <p>Lê do contexto: cadeia de certificados, {@code referenceTimestamp}, URI da política e
 * o atributo {@code contentDigest} (payload attached). Escreve: {@code jadesSession}
 * (sessão DSS congelada) e {@code signingInputBytes}.
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
                    "Cadeia de certificados ausente no contexto. Verifique se o step pkix-chain-validation foi executado.",
                    context);
        }

        String contentDigest = context
                .getAttribute(SigningKeys.CONTENT_DIGEST, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_HASH_VERIFICATION_FAILED,
                        "A impressão digital do conteúdo não foi encontrada no contexto. "
                                + "Verifique se o step framed-content-digest foi executado."));

        byte[] payload;
        try {
            payload = Base64.getUrlDecoder().decode(contentDigest);
        } catch (IllegalArgumentException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Impressão digital do conteúdo não é base64url válido: " + e.getMessage(), context);
        }
        if (!(chain[0].getPublicKey() instanceof RSAPublicKey)) {
            return StepResult.failure(getName(), SignatureExceptionCode.CERT_UNSUPPORTED_ALGORITHM,
                    "A política 0.2.0 admite somente RS256; chave do signatário: "
                            + chain[0].getPublicKey().getAlgorithm(), context);
        }

        try {
            JadesSigningSession session = signingService.newSession(new JadesSigningService.Request(
                    List.of(chain),
                    payload,
                    context.getReferenceTimestamp(),
                    context.getPolicyIdentifierUri()));

            byte[] dataToSign = signingService.dataToSign(session);

            SigningContext updated = context.toBuilder()
                    .attribute(JADES_SESSION_KEY, session)
                    .attribute(SigningKeys.SIGNING_INPUT_BYTES, dataToSign)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao preparar os dados a assinar (JAdES): " + e.getMessage(), e);
        }
    }
}
