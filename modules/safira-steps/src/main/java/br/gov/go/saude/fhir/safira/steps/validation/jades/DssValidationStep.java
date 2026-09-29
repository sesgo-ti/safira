/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.validation.jades;

import br.gov.go.saude.fhir.safira.engine.domain.StepResult;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.pipelines.StepId;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationContext;
import br.gov.go.saude.fhir.safira.engine.domain.validation.ValidationStep;
import br.gov.go.saude.fhir.safira.jades.JadesValidationService;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifiers;
import br.gov.go.saude.fhir.safira.jades.adapter.EvidenceRevocationSources;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.revocation.LibRevocationEvidence;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import br.gov.go.saude.truststore.icpbrasil.service.revocation.RevocationService;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.validation.reports.Reports;

import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code dss-validation}: verificação criptográfica JWS (4.3), cadeias, revogação (6) e,
 * em JAdES-B-T, o carimbo com prova de existência (5), pelo validador do EU DSS.
 *
 * <p>Âncoras: acervo ICP-Brasil (lib icpbrasil-truststore) e, em B-T, as do trust store TSA da
 * política. Revogação: somente evidências obtidas e verificadas pela lib
 * ({@link LibRevocationEvidence}); o DSS não acessa a rede. Exige {@code TOTAL_PASSED} e o formato
 * {@code JAdES-BASELINE-B}/{@code -T} correspondente ao nível identificado.
 */
// DIVERGENCIA-IG D7: validade histórica (intervalo I) em B-T delegada ao DSS; a lib valida só o instante atual
@StepId("dss-validation")
public class DssValidationStep implements ValidationStep {

    private final RevocationService revocationService;
    private final TrustMaterialSource trustMaterialSource;
    private final SafiraPolicyProperties policy;
    private final JadesValidationService validationService = new JadesValidationService();

    public DssValidationStep(RevocationService revocationService, TrustMaterialSource trustMaterialSource,
                             SafiraPolicyProperties policy) {
        this.revocationService = revocationService;
        this.trustMaterialSource = trustMaterialSource;
        this.policy = policy;
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        String jws = context.getAttribute(ValidationKeys.JWS_JSON, String.class).orElseThrow();
        JadesLevel level = context.getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class).orElseThrow();
        List<X509Certificate> signerChain = context.getCertificateChain().orElseThrow();

        List<List<X509Certificate>> chains = new ArrayList<>();
        chains.add(signerChain);
        List<X509Certificate> anchors = new ArrayList<>(icpBrasilAnchors());
        if (level == JadesLevel.B_T) {
            try {
                Inspection inspection = TimestampTokenInspector.inspect(TimestampTokenInspector.tokenFromJws(jws));
                Optional<TsaPolicy> tsaPolicy = TsaChainVerification.selectPolicy(policy, inspection);
                if (tsaPolicy.isEmpty()) {
                    return fail(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                            "Política do carimbo " + inspection.policyOid() + " não consta de safira.policy.tsa-policies.", context);
                }
                List<X509Certificate> tsaAnchors = TsaTrustStores.load(tsaPolicy.get().trustStore().reference());
                Optional<List<X509Certificate>> tsaChain = TsaChainVerification.chainToAnchor(inspection, tsaAnchors);
                if (tsaChain.isEmpty()) {
                    return fail(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED,
                            "A cadeia da TSA não termina em âncora do trust store da política " + tsaPolicy.get().oid() + ".",
                            context);
                }
                chains.add(tsaChain.get());
                anchors.addAll(tsaAnchors);
            } catch (TimestampTokenException e) {
                return fail(e.getCode(), e.getMessage(), context);
            } catch (IllegalArgumentException e) {
                return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, e.getMessage(), context);
            }
        }

        LibRevocationEvidence.Collected evidence;
        switch (LibRevocationEvidence.collect(revocationService, chains)) {
            case LibRevocationEvidence.Outcome.Failed failed -> {
                return fail(failed.code(), failed.diagnostics(), context);
            }
            case LibRevocationEvidence.Outcome.Ok ok -> evidence = ok.collected();
        }
        if (level == JadesLevel.B_B && !evidence.revoked().isEmpty()) {
            return fail(SignatureExceptionCode.CERT_REVOKED, "Certificado atualmente revogado: "
                    + evidence.revoked().getFirst().getSubjectX500Principal().getName() + ".", context);
        }

        Reports reports = validationService.validate(jws, CertificateVerifiers.create(anchors,
                EvidenceRevocationSources.ocspFromEvidence(evidence.ocspResponses()),
                EvidenceRevocationSources.crlFromEvidence(evidence.crls())));
        SimpleReport report = reports.getSimpleReport();
        String id = report.getFirstSignatureId();
        Indication indication = report.getIndication(id);
        if (indication != Indication.TOTAL_PASSED) {
            SubIndication sub = report.getSubIndication(id);
            return fail(codeFor(indication, sub), "EU DSS: " + indication + (sub == null ? "" : "/" + sub)
                    + " " + report.getAdESValidationErrors(id).stream().map(m -> m.getValue()).toList(), context);
        }
        SignatureLevel expected = level == JadesLevel.B_B ? SignatureLevel.JAdES_BASELINE_B : SignatureLevel.JAdES_BASELINE_T;
        if (report.getSignatureFormat(id) != expected) {
            return fail(SignatureExceptionCode.VALIDATION_JADES_LEVEL_INVALID,
                    "EU DSS classificou a assinatura como " + report.getSignatureFormat(id) + "; esperado " + expected + ".",
                    context);
        }
        return StepResult.success(getName(), context);
    }

    private List<X509Certificate> icpBrasilAnchors() {
        return trustMaterialSource.current().stream()
                .flatMap(trust -> trust.anchors().stream())
                .map(TrustAnchor::getTrustedCert)
                .toList();
    }

    private static SignatureExceptionCode codeFor(Indication indication, SubIndication sub) {
        if (sub == null) {
            return indication == Indication.INDETERMINATE
                    ? SignatureExceptionCode.VALIDATION_INDETERMINATE
                    : SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
        }
        return switch (sub) {
            case SIG_CRYPTO_FAILURE, HASH_FAILURE -> SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED;
            case FORMAT_FAILURE -> SignatureExceptionCode.FORMAT_JWS_MALFORMED;
            case REVOKED, REVOKED_NO_POE, REVOKED_CA_NO_POE -> SignatureExceptionCode.CERT_REVOKED;
            case EXPIRED, OUT_OF_BOUNDS_NO_POE, OUT_OF_BOUNDS_NOT_REVOKED -> SignatureExceptionCode.CERT_EXPIRED;
            case NOT_YET_VALID -> SignatureExceptionCode.CERT_NOT_YET_VALID;
            case TRY_LATER, REVOCATION_OUT_OF_BOUNDS_NO_POE -> SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN;
            case NO_CERTIFICATE_CHAIN_FOUND, NO_CERTIFICATE_CHAIN_FOUND_NO_POE -> SignatureExceptionCode.CERT_NOT_ICP_BRASIL;
            default -> indication == Indication.INDETERMINATE
                    ? SignatureExceptionCode.VALIDATION_INDETERMINATE
                    : SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
        };
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
