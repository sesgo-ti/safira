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
import br.gov.go.saude.fhir.safira.jades.EcdsaSignatureFormats;
import br.gov.go.saude.fhir.safira.jades.JadesSigningService;
import br.gov.go.saude.fhir.safira.jades.JadesSigningSession;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.JwsFinalStep;

import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Base64;

/**
 * Passo {@code jades-assemble}: entrega o valor de assinatura ao EU DSS e publica o JWS
 * General JSON Serialization final no atributo {@code jwsFinal}.
 *
 * <p>Lê do contexto: {@code jadesSession} e o atributo {@code signature} (base64url)
 * produzido pelo {@code crypto-signing}. Para ES256, o valor R||S é transcodificado para
 * DER — formato JCA esperado pelo DSS, que o converte de volta ao montar o JWS.
 */
@StepId("jades-assemble")
public class JadesAssembleStep implements SigningStep {

    private final JadesSigningService signingService;

    public JadesAssembleStep() {
        this(new JadesSigningService());
    }

    public JadesAssembleStep(JadesSigningService signingService) {
        this.signingService = signingService;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        JadesSigningSession session = context
                .getAttribute(JadesDataToSignStep.JADES_SESSION_KEY, JadesSigningSession.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "Sessão JAdES não encontrada no contexto. "
                                + "Verifique se o step jades-data-to-sign foi executado."));

        String signatureB64Url = context
                .getAttribute(CryptoSigningStep.SIGNATURE_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "Valor de assinatura não encontrado no contexto. "
                                + "Verifique se o step crypto-signing foi executado."));

        try {
            byte[] signatureValue = Base64.getUrlDecoder().decode(signatureB64Url);

            if (isEcdsa(context)) {
                signatureValue = EcdsaSignatureFormats.concatToDer(signatureValue);
            }

            String jwsFinal = signingService.sign(session, signatureValue);

            SigningContext updated = context.toBuilder()
                    .attribute(JwsFinalStep.JWS_FINAL_KEY, jwsFinal)
                    .build();

            return StepResult.success(getName(), updated);
        } catch (IllegalArgumentException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.FORMAT_BASE64_INVALID,
                    "Valor de assinatura não é base64url válido: " + e.getMessage(), context);
        } catch (Exception e) {
            throw new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                    "Erro ao montar o JWS JAdES: " + e.getMessage(), e);
        }
    }

    private boolean isEcdsa(SigningContext context) {
        return context.getSignerCertificate()
                .map(X509Certificate::getPublicKey)
                .filter(ECPublicKey.class::isInstance)
                .isPresent();
    }
}
