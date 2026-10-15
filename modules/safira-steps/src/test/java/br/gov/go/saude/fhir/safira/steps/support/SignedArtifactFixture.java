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
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;
import br.gov.go.saude.fhir.safira.testkit.TsaHttpLocal;
import br.gov.go.saude.fhir.safira.steps.policy.Policy020;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.signing.CertificatePolicyStep;
import br.gov.go.saude.fhir.safira.steps.signing.CryptoSigningStep;
import br.gov.go.saude.fhir.safira.steps.signing.FhirSignatureStep;
import br.gov.go.saude.fhir.safira.steps.signing.FramedContentDigestStep;
import br.gov.go.saude.fhir.safira.steps.signing.PkixChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.SigningKeys;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesAssembleStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesDataToSignStep;
import br.gov.go.saude.fhir.safira.steps.signing.jades.JadesExtensionStep;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import br.gov.go.saude.fhir.safira.steps.validation.jades.ValidationKeys;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;

import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Artefato assinado real (Signature, Bundle, Provenance) produzido pelos steps de assinatura da
 * política 0.2.0 com a PKI de teste — insumo dos testes de validação.
 */
public final class SignedArtifactFixture {

    /** Snapshot do acervo que a fonte informada entrega agora. */
    public static AcervoDeConfianca acervo(FonteDeConfianca source) {
        return source.atual().orElseThrow();
    }

    /** Contexto com o snapshot que {@code validation-context} guardaria para essa fonte. */
    public static ValidationContext comAcervo(ValidationContext context, FonteDeConfianca source) {
        return context.toBuilder().attribute(ValidationKeys.ACERVO, acervo(source)).build();
    }

    public static final String U1 = "urn:uuid:3fa85f64-5717-4562-b3fc-2c963f66afa6";
    public static final String U2 = "urn:uuid:9b2b8c1e-2f4a-4d5b-8c6d-7e8f9a0b1c2d";

    public static final String BUNDLE = "{\"resourceType\":\"Bundle\",\"type\":\"collection\",\"entry\":["
            + "{\"fullUrl\":\"" + U1 + "\",\"resource\":{\"resourceType\":\"Patient\",\"id\":\"p1\",\"gender\":\"female\"}},"
            + "{\"fullUrl\":\"" + U2 + "\",\"resource\":{\"resourceType\":\"Observation\",\"status\":\"final\","
            + "\"subject\":{\"reference\":\"" + U1 + "\"},\"valueQuantity\":{\"value\":13.50}}}]}";

    public static final String PROVENANCE = "{\"resourceType\":\"Provenance\",\"target\":[{\"reference\":\"" + U2
            + "\"},{\"reference\":\"" + U1 + "\"}],\"recorded\":\"2026-01-10T10:05:00-03:00\","
            + "\"agent\":[{\"who\":{\"identifier\":{\"system\":\"urn:brasil:cpf\",\"value\":\"" + PkiIcpSimulada.CPF + "\"}}}]}";

    private SignedArtifactFixture() {
    }

    /**
     * @param iat instante de referência da assinatura
     * @param tsa TSA local para o resultado {@code tsa}; nulo produz JAdES-B-B
     */
    public static SigningResult sign(PkiIcpSimulada pki, SafiraPolicyProperties policy, long iat, TsaHttpLocal tsa) {
        return sign(pki, policy, iat, tsa, true);
    }

    /**
     * Assina sem a validação PKIX da cadeia, para produzir artefatos que o lado
     * da assinatura recusaria (certificado do signatário inválido) e exercitar a validação.
     */
    public static SigningResult signSemVerificarCadeia(PkiIcpSimulada pki, SafiraPolicyProperties policy) {
        return sign(pki, policy, Instant.now().getEpochSecond(), null, false);
    }

    private static SigningResult sign(PkiIcpSimulada pki, SafiraPolicyProperties policy, long iat, TsaHttpLocal tsa,
                                      boolean verificarCadeia) {
        VerificadoresDss verifiers = new VerificadoresDss(
                FonteDeTeste.com(pki.raiz(), pki.ac()),
                CertificateVerifierFactory.offline(pki.fonteOcsp(), null));
        try {
            SigningContext context = SigningContext.builder()
                    .bundleJson(LosslessJson.parseObject(BUNDLE))
                    .provenanceJson(LosslessJson.parseObject(PROVENANCE))
                    .rawCertificateChain(List.of(Base64.getEncoder().encodeToString(pki.signatario().getEncoded())))
                    .cryptoMaterial(new CryptoMaterial.PemMaterial(pki.chavePrivadaSignatarioPemBase64(), null))
                    .referenceTimestamp(iat)
                    .strategy(tsa == null ? TimestampStrategy.IAT : TimestampStrategy.TSA)
                    .policyIdentifierUri(Policy020.POLICY_URI)
                    .operationalConfig(TestConfigs.operational(tsa == null ? null : tsa.url()))
                    .build();
            List<Step<SigningContext>> verificacoes = new ArrayList<>();
            if (verificarCadeia) {
                verificacoes.add(new PkixChainValidationStep(verifiers, policy));
            } else {
                // simula a evidência do pkix-chain-validation pulado
                context = context.toBuilder().certificateChain(pki.cadeia().toArray(X509Certificate[]::new))
                        .attribute(SigningKeys.ACERVO, acervo(FonteDeTeste.com(pki.raiz(), pki.ac())))
                        .attribute(SigningKeys.CADEIA_APROVADA_DSS, true)
                        .build();
            }
            verificacoes.add(new CertificatePolicyStep(policy));
            List<Step<SigningContext>> steps = List.of(
                    new FramedContentDigestStep(),
                    new JadesDataToSignStep(),
                    new CryptoSigningStep(),
                    new JadesAssembleStep(),
                    new JadesExtensionStep(new JadesExtensionService(), policy),
                    new FhirSignatureStep());
            List<Step<SigningContext>> todos = new ArrayList<>(verificacoes);
            todos.addAll(steps);
            for (Step<SigningContext> step : todos) {
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

    public static SigningResult sign(PkiIcpSimulada pki, SafiraPolicyProperties policy) {
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
