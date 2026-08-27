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
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.CompositeRevocationSource;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.jades.adapter.OnlineRevocationSources;
import br.gov.go.saude.fhir.safira.jades.adapter.TspSources;
import br.gov.go.saude.fhir.safira.steps.config.SafiraJadesProperties;
import br.gov.go.saude.fhir.safira.steps.signing.ChainValidationStep;
import br.gov.go.saude.fhir.safira.steps.signing.JwsFinalStep;
import br.gov.go.saude.fhir.safira.steps.signing.revocation.RevocationEvidence;
import eu.europa.esig.dss.alert.exception.AlertException;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.exception.DSSExternalResourceException;
import eu.europa.esig.dss.spi.validation.CertificateVerifier;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.tsp.TSPSource;

import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;

/**
 * Passo {@code jades-extension}: eleva o nível da assinatura conforme a estratégia de
 * carimbo e o nível alvo configurado (ETSI TS 119 182-1 §6.3, níveis cumulativos):
 *
 * <ul>
 *   <li>estratégia {@code iat} → permanece <b>B-B</b> (no-op);</li>
 *   <li>estratégia {@code tsa} → <b>B-T</b>: {@code sigTst} (token RFC 3161 sobre o
 *       signature value) dentro do container {@code etsiU};</li>
 *   <li>{@code tsa} + {@code target-level: B-LT} → <b>B-LT</b>: material completo de
 *       validação embutido ({@code xVals}/{@code rVals}/{@code tstVD}), priorizando as
 *       evidências coletadas pelo {@code chain-validation} com fallback online (AIA/CDP)
 *       para material fora da cadeia do signatário — ex.: certificado da TSA;</li>
 *   <li>{@code tsa} + {@code target-level: B-LTA} → <b>B-LTA</b>: acrescenta {@code arcTst}
 *       como último elemento do {@code etsiU}.</li>
 * </ul>
 *
 * <p>O {@code iat} permanece presente em todas as estratégias — carimbos adicionam prova,
 * não substituem o instante declarado (§5.1.11).
 */
@StepId("jades-extension")
public class JadesExtensionStep implements SigningStep {

    private final JadesExtensionService extensionService;
    private final SafiraJadesProperties.TargetLevel targetLevel;

    public JadesExtensionStep() {
        this(new JadesExtensionService(), SafiraJadesProperties.TargetLevel.B_T);
    }

    public JadesExtensionStep(JadesExtensionService extensionService,
                              SafiraJadesProperties.TargetLevel targetLevel) {
        this.extensionService = extensionService;
        this.targetLevel = targetLevel;
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

        SignatureLevel target = resolveTarget();

        try {
            TSPSource tspSource = TspSources.online(tsaUrl, verification.tsaTimeout());
            CertificateVerifier verifier = target == SignatureLevel.JAdES_BASELINE_T
                    ? new CommonCertificateVerifier()
                    : buildLtvVerifier(context, verification);

            String extended = extensionService.extend(jws, target, tspSource, verifier);

            SigningContext updated = context.toBuilder()
                    .attribute(JwsFinalStep.JWS_FINAL_KEY, extended)
                    .build();
            return StepResult.success(getName(), updated);
        } catch (AlertException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.REVOCATION_OCSP_UNAVAILABLE,
                    "Material de validação incompleto para o nível " + target + ": " + e.getMessage(), context);
        } catch (DSSExternalResourceException e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_UNAVAILABLE,
                    "TSA inacessível em " + tsaUrl + ": " + e.getMessage(), context);
        } catch (Exception e) {
            return StepResult.failure(getName(), SignatureExceptionCode.TSA_INVALID_RESPONSE,
                    "Falha ao estender a assinatura para " + target + ": " + e.getMessage(), context);
        }
    }

    private SignatureLevel resolveTarget() {
        return switch (targetLevel) {
            case B_T -> SignatureLevel.JAdES_BASELINE_T;
            case B_LT -> SignatureLevel.JAdES_BASELINE_LT;
            case B_LTA -> SignatureLevel.JAdES_BASELINE_LTA;
        };
    }

    /**
     * Verificador para extensão LT/LTA: âncora = raiz da cadeia (já aprovada pelo
     * {@code chain-validation} contra o trust store ICP-Brasil); revogação = evidências
     * coletadas na assinatura com fallback online (AIA/CDP) para o material da TSA.
     */
    @SuppressWarnings("unchecked")
    private CertificateVerifier buildLtvVerifier(SigningContext context,
                                                 SafiraOperationalConfigProperties.VerificationProps verification) {
        X509Certificate[] chain = context.getCertificateChain()
                .orElseThrow(() -> new StepException(SignatureExceptionCode.CERT_CHAIN_INCOMPLETE,
                        "Cadeia de certificados ausente no contexto para extensão LTV."));
        X509Certificate trustAnchor = chain[chain.length - 1];

        List<RevocationEvidence> evidences = context
                .getAttribute(ChainValidationStep.REVOCATION_EVIDENCES_KEY, List.class)
                .orElse(List.of());

        List<byte[]> ocspDers = evidences.stream()
                .filter(e -> "OCSP".equalsIgnoreCase(e.source()))
                .map(e -> Base64.getDecoder().decode(e.responseDerBase64()))
                .toList();
        List<byte[]> crlDers = evidences.stream()
                .filter(e -> "CRL".equalsIgnoreCase(e.source()))
                .map(e -> Base64.getDecoder().decode(e.responseDerBase64()))
                .toList();

        RevocationSource<OCSP> ocsp = CompositeRevocationSource.of(
                EvidenceRevocationSources.ocspFromEvidence(ocspDers),
                OnlineRevocationSources.ocsp(verification.ocspTimeout()));
        RevocationSource<CRL> crl = CompositeRevocationSource.of(
                EvidenceRevocationSources.crlFromEvidence(crlDers),
                OnlineRevocationSources.crl(verification.crlTimeout()));

        return CertificateVerifiers.create(List.of(trustAnchor), ocsp, crl);
    }
}
