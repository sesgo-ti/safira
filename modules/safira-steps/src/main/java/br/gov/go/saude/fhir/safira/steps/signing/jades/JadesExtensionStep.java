/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.signing.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepException;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningStep;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSources;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;

/**
 * Passo {@code jades-extension}: etapas 12 e 13 do caso de uso de criação.
 *
 * <ul>
 *   <li>resultado {@code iat} → permanece JAdES-B-B (sem {@code header});</li>
 *   <li>resultado {@code tsa} → JAdES-B-T: carimbo RFC 3161 com nonce e {@code reqPolicy} da
 *       política TSA selecionada, incorporado como único {@code sigTst} de {@code etsiU} em claro.</li>
 * </ul>
 *
 * <p>O {@code iat} permanece no protected header em ambos os resultados. A política TSA usada é
 * a primeira de {@code safira.policy.tsa-policies} e fica no atributo {@link #TSA_POLICY_OID_KEY}.
 */
@StepId("jades-extension")
public class JadesExtensionStep implements SigningStep {

    public static final String TSA_POLICY_OID_KEY = "tsaPolicyOid";

    private final JadesExtensionService extensionService;
    private final SafiraPolicyProperties policy;

    public JadesExtensionStep(JadesExtensionService extensionService, SafiraPolicyProperties policy) {
        this.extensionService = extensionService;
        this.policy = policy;
    }

    @Override
    public StepResult<SigningContext> execute(SigningContext context) throws StepException {
        if (context.getStrategy() != TimestampStrategy.TSA) {
            return StepResult.success(getName(), context);
        }
        String jws = context.getAttribute(SigningKeys.JWS_FINAL, String.class)
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CRYPTO_SIGNATURE_CREATION_FAILED,
                        "JWS não encontrado no contexto. Verifique se o step jades-assemble foi executado."));
        if (policy.tsaPolicyList().isEmpty()) {
            return StepResult.failure(getName(), SignatureExceptionCode.CONFIG_MISSING_PARAMETER,
                    "Resultado 'tsa' exige safira.policy.tsa-policies.", context);
        }
        TsaPolicy tsaPolicy = policy.tsaPolicyList().getFirst();
        var verification = context.getOperationalConfig().verification();
        String tsaUrl = verification.tsaUrl();
        try {
            String extended = extensionService.extendToBaselineT(jws,
                    TspSources.online(tsaUrl, verification.tsaTimeout(), tsaPolicy.oid()));
            return StepResult.success(getName(), context.toBuilder()
                    .attribute(SigningKeys.JWS_FINAL, extended)
                    .attribute(TSA_POLICY_OID_KEY, tsaPolicy.oid())
                    .build());
        } catch (DSSExternalResourceException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_UNAVAILABLE,
                    "TSA inacessível em " + tsaUrl + ": " + e.getMessage(), context);
        } catch (Exception e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_RESPONSE,
                    "Resposta da TSA rejeitada (status, nonce, imprint ou política): " + e.getMessage(), context);
        }
    }
}
