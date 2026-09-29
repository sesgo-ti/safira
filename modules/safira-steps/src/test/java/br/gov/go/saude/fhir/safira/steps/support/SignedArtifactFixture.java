/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.support;

import br.gov.go.saude.fhir.safira.engine.domain.CryptoMaterial;
import br.gov.go.saude.fhir.safira.engine.domain.Step;
import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.TimestampStrategy;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningContext;
import br.gov.go.saude.fhir.safira.engine.domain.signing.SigningResult;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.jades.JadesExtensionService;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.signing.CertificatePolicyStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.FhirSignatureStep;
import br.gov.go.saude.fhir.safira.steps.signing.FramedContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.PkixChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesAssembleStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesDataToSignStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesExtensionStep;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.PkixCertificateValidator;

import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Artefato assinado real (Signature, Bundle, Provenance) produzido pelos steps de assinatura da
 * política 0.2.0 com a PKI de teste — insumo dos testes de validação.
 */
public final class SignedArtifactFixture {

    public static final String U1 = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6";
    public static final String U2 = "urn:uuid:9b2b8c1e-2f4a-4d5b-8c6d-7e8f9a0b1c2d";

    public static final String BUNDLE = "{\"resourceType\":\"Bundle\",\"type\":\"collection\",\"entry\":["
            + "{\"fullUrl\":\"" + U1 + "\",\"resource\":{\"resourceType\":\"Patient\",\"id\":\"p1\",\"gender\":\"female\"}},"
            + "{\"fullUrl\":\"" + U2 + "\",\"resource\":{\"resourceType\":\"Observation\",\"status\":\"final\","
            + "\"subject\":{\"reference\":\"" + U1 + "\"},\"valueQuantity\":{\"value\":13.50}}}]}";

    public static final String PROVENANCE = "{\"resourceType\":\"Provenance\",\"target\":[{\"reference\":\"" + U2
            + "\"},{\"reference\":\"" + U1 + "\"}],\"recorded\":\"2026-01-10T10:05:00-03:00\","
            + "\"agent\":[{\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"" + TestPki.TEST_CPF + "\"}}}]}";

    private SignedArtifactFixture() {
    }

    /**
     * @param iat instante de referência da assinatura
     * @param tsa TSA local para o resultado {@code tsa}; nulo produz JAdES-B-B
     */
    public static SigningResult sign(TestPki pki, SafiraPolicyProperties policy, long iat, TestPki.FakeTsa tsa) {
        PkixCertificateValidator validator = mock(PkixCertificateValidator.class);
        when(validator.validate(any(), anyCollection()))
                .thenReturn(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of()));
        try {
            SigningContext context = SigningContext.builder()
                    .bundleJson(LosslessJson.parseObject(BUNDLE))
                    .provenanceJson(LosslessJson.parseObject(PROVENANCE))
                    .rawCertificateChain(List.of(Base64.getEncoder().encodeToString(pki.leafCert.getEncoded())))
                    .cryptoMaterial(new CryptoMaterial.PemMaterial(pki.leafKeyPemBase64(), null))
                    .referenceTimestamp(iat)
                    .strategy(tsa == null ? TimestampStrategy.IAT : TimestampStrategy.TSA)
                    .policyIdentifierUri(Policy020.POLICY_URI)
                    .operationalConfig(TestConfigs.operational(tsa == null ? null : tsa.url()))
                    .build();
            List<Step<SigningContext>> steps = List.of(
                    new PkixChainValidationStep(validator),
                    new CertificatePolicyStep(policy),
                    new FramedContentDigestStep(),
                    new JadesDataToSignStep(),
                    new CryptoSigningStep(),
                    new JadesAssembleStep(),
                    new JadesExtensionStep(new JadesExtensionService(), policy),
                    new FhirSignatureStep());
            for (Step<SigningContext> step : steps) {
                StepResult<SigningContext> result = step.execute(context);
                if (!result.isSuccess()) {
                    throw new IllegalStateException("Falha ao assinar no step " + step.getName() + ": "
                            + ((StepResult.Failure<SigningContext>) result).diagnostics());
                }
                context = result.context();
            }
            return context.getSigningResult();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static SigningResult sign(TestPki pki, SafiraPolicyProperties policy) {
        return sign(pki, policy, Instant.now().getEpochSecond(), null);
    }

    /**
     * Contexto de validação com o trio assinado. O timestamp de referência fica 2 s à frente para
     * que o intervalo de um carimbo recém-emitido (genTime + accuracy) não o ultrapasse (validar 5.4).
     */
    public static ValidationContext validationContext(SigningResult signed) {
        return ValidationContext.builder()
                .signatureJson(LosslessJson.parseObject(signed.signatureJson()))
                .bundleJson(LosslessJson.parseObject(BUNDLE))
                .provenanceJson(LosslessJson.parseObject(signed.provenanceJson()))
                .referenceTimestamp(Instant.now().getEpochSecond() + 2)
                .policyIdentifierUri(Policy020.POLICY_URI)
                .operationalConfig(TestConfigs.operational())
                .build();
    }
}
