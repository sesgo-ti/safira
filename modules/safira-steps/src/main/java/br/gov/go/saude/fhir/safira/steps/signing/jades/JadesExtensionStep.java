/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSources;
import br.gov.go.saude.fhir.safira.steps.signing.JwsFinalStep;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

/**
 * Passo {@code jades-extension} (política 2.0.0): eleva o nível da assinatura conforme a
 * estratégia de carimbo (ETSI TS 119 182-1 §6.3, níveis cumulativos):
 *
 * <ul>
 *   <li>estratégia {@code iat} → permanece <b>B-B</b> (no-op);</li>
 *   <li>estratégia {@code tsa} → <b>B-T</b>: o EU DSS incorpora {@code sigTst} (token
 *       RFC 3161 sobre o signature value) dentro do container {@code etsiU}.</li>
 * </ul>
 *
 * <p>O {@code iat} permanece presente em ambas as estratégias — B-T <em>adiciona</em> o
 * carimbo, não substitui o instante declarado (§5.1.11).
 */
@StepId("jades-extension")
public class JadesExtensionStep implements SigningStep {

    private final JadesExtensionService extensionService;

    public JadesExtensionStep() {
        this(new JadesExtensionService());
    }

    public JadesExtensionStep(JadesExtensionService extensionService) {
        this.extensionService = extensionService;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        if (context.getStrategy() != TimestampStrategy.TSA) {
            return StepResult.success(getName(), context);
        }

        String jws = context.getAttribute(JwsFinalStep.JWS_FINAL_KEY, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "JWS não encontrado no contexto. Verifique se o step jades-assemble foi executado."));

        SafiraOperationalConfigProperties.VerificationProps verification =
                context.getOperationalConfig().verification();
        String tsaUrl = verification.tsaUrl();
        if (tsaUrl == null || tsaUrl.isBlank()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_TSA_CONFIG_MISSING,
                    "Estratégia TSA selecionada, mas nenhuma URL de TSA está configurada "
                            + "(safira.operational.verification.tsa-url).", context);
        }

        try {
            TSPSource tspSource = TspSources.online(tsaUrl, verification.tsaTimeout());
            String extended = extensionService.extend(
                    jws, SignatureLevel.JAdES_BASELINE_T, tspSource, new CommonCertificateVerifier());

            SigningContext updated = context.toBuilder()
                    .attribute(JwsFinalStep.JWS_FINAL_KEY, extended)
                    .build();
            return StepResult.success(getName(), updated);
        } catch (DSSExternalResourceException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_UNAVAILABLE,
                    "TSA inacessível em " + tsaUrl + ": " + e.getMessage(), context);
        } catch (Exception e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_RESPONSE,
                    "Falha ao incorporar carimbo de tempo (B-T): " + e.getMessage(), context);
        }
    }
}
