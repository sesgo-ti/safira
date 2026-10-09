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
import br.gov.go.saude.fhir.safira.steps.dss.DssOutcomes;
import br.gov.go.saude.fhir.safira.steps.dss.PoliticaDeValidacaoDss;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code dss-validation}: o EU DSS decide a assinatura — verificação criptográfica JWS
 * (4.3), construção da cadeia pelo {@code x5c} e pelas ACs do acervo (sem AIA), revogação
 * OCSP/CRL obtida pelo próprio DSS só para cadeias que terminam numa âncora (6) e, em JAdES-B-T,
 * o carimbo e a cadeia da TSA com prova de existência (5).
 *
 * <p>Âncoras: raízes do acervo ICP-Brasil e, em B-T, as do trust store TSA da política, cuja
 * cadeia do carimbo precisa terminar numa delas; a do signatário, mesmo aprovada pelo DSS, precisa
 * terminar numa raiz do acervo, senão {@code CERT.NOT-ICP-BRASIL}. Tempo: em B-B o DSS valida no instante atual
 * (certificado revogado agora → {@code REVOKED_NO_POE} → {@code CERT.REVOKED}); em B-T o carimbo
 * é a POE e revogação posterior a ele não invalida a assinatura.
 *
 * <p>Política de validação: a versionada ({@link PoliticaDeValidacaoDss}, derivada da padrão do
 * DSS 6.5) com a lista explícita dos OIDs da allowlist. Aqui o {@code PolicyIds} é defesa em
 * profundidade: o {@code signer-certificate} roda antes no pipeline e já recusa a folha fora da
 * allowlist; se ainda assim o DSS recusar por {@code PolicyIds}, o código é
 * {@code VALIDATION.POLICY-COMPLIANCE-FAILED} (validar 4.1). As demais regras SES-GO (emissor da
 * allowlist, tipo, chave, keyUsage, identidade, janela do carimbo) ficam nos passos próprios.
 *
 * <p>Só no sucesso grava {@link ValidationKeys#DSS_APROVADO}, evidência exigida por {@code validation-outcome}.
 */
// DIVERGENCIA-IG D7: validade histórica (intervalo I) em B-T decidida pelo DSS com o carimbo como POE
@StepId("dss-validation")
public class DssValidationStep implements ValidationStep {

    private static final Logger log = LoggerFactory.getLogger(DssValidationStep.class);

    private final VerificadoresDss verifiers;
    private final SafiraPolicyProperties policy;
    private final Optional<JadesValidationService> validationService;

    public DssValidationStep(VerificadoresDss verifiers, SafiraPolicyProperties policy) {
        this.verifiers = verifiers;
        this.policy = policy;
        this.validationService = PoliticaDeValidacaoDss.da(policy).map(JadesValidationService::new);
    }

    @Override
    public StepResult<ValidationContext> execute(ValidationContext context) {
        String jws = context.getAttribute(ValidationKeys.JWS_JSON, String.class).orElseThrow();
        JadesLevel level = context.getAttribute(ValidationKeys.JADES_LEVEL, JadesLevel.class).orElseThrow();

        List<X509Certificate> tsaAnchors = List.of();
        TsaPolicy tsaPolicy = null;
        if (level == JadesLevel.B_T) {
            try {
                Inspection inspection = TimestampTokenInspector.inspect(TimestampTokenInspector.tokenFromJws(jws));
                Optional<TsaPolicy> selected = TsaChainVerification.selectPolicy(policy, inspection);
                if (selected.isEmpty()) {
                    return fail(SignatureExceptionCode.TSA_POLICY_UNSUPPORTED,
                            "Política do carimbo " + inspection.policyOid() + " não consta de safira.policy.tsa-policies.", context);
                }
                tsaPolicy = selected.get();
                tsaAnchors = TsaTrustStores.load(tsaPolicy.trustStore().reference());
            } catch (TimestampTokenException e) {
                return fail(e.getCode(), e.getMessage(), context);
            } catch (IllegalArgumentException e) {
                log.error("Trust store da política TSA indisponível", e);
                return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                        "Trust store da política TSA indisponível.", context);
            }
        }

        Optional<AcervoDeConfianca> acervo = context.getAttribute(ValidationKeys.ACERVO, AcervoDeConfianca.class);
        if (acervo.isEmpty()) {
            return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, "Acervo ICP-Brasil indisponível.", context);
        }
        if (validationService.isEmpty()) {
            return fail(SignatureExceptionCode.CONFIG_INVALID_PARAMETER,
                    "safira.policy.accepted-certificate-policies não tem OID de política válido.", context);
        }
        CommonCertificateVerifier verifier = verifiers.paraOperacao(acervo.get(), tsaAnchors);
        Reports reports = validationService.get().validate(jws, verifier);
        SimpleReport report = reports.getSimpleReport();
        String id = report.getFirstSignatureId();

        if (level == JadesLevel.B_T) {
            Optional<PolicyViolation> timestampFailure = DssOutcomes.signatureTimestamp(reports, id, tsaAnchors, tsaPolicy.oid());
            if (timestampFailure.isPresent()) {
                return fail(timestampFailure.get().code(), timestampFailure.get().diagnostics(), context);
            }
        }

        Indication indication = report.getIndication(id);
        if (indication != Indication.TOTAL_PASSED) {
            SubIndication sub = report.getSubIndication(id);
            List<Message> errors = report.getAdESValidationErrors(id);
            SignatureExceptionCode code = DssOutcomes.code(indication, sub,
                    reports.getDiagnosticData().getSignatureById(id).getCertificateChain(),
                    reports.getDiagnosticData().getValidationDate(), errors);
            // defesa em profundidade: o perfil (signer-certificate) já recusou a folha fora da allowlist
            if (code == SignatureExceptionCode.CERT_NOT_ICP_BRASIL && DssOutcomes.policyIdsRejected(errors)) {
                code = SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
            }
            return fail(code, "EU DSS: " + indication + (sub == null ? "" : "/" + sub)
                    + " " + DssOutcomes.messages(errors), context);
        }
        // em B-T as âncoras da TSA estão no mesmo verificador: a cadeia do signatário precisa terminar no acervo
        if (!terminaNoAcervo(reports.getDiagnosticData().getSignatureById(id).getCertificateChain(), acervo.get())) {
            return fail(SignatureExceptionCode.CERT_NOT_ICP_BRASIL,
                    "A cadeia do signatário montada pelo EU DSS não termina numa raiz do acervo ICP-Brasil.", context);
        }
        SignatureLevel expected = level == JadesLevel.B_B ? SignatureLevel.JAdES_BASELINE_B : SignatureLevel.JAdES_BASELINE_T;
        if (report.getSignatureFormat(id) != expected) {
            return fail(SignatureExceptionCode.VALIDATION_JADES_LEVEL_INVALID,
                    "EU DSS classificou a assinatura como " + report.getSignatureFormat(id) + "; esperado " + expected + ".",
                    context);
        }
        return StepResult.success(getName(), context.toBuilder().attribute(ValidationKeys.DSS_APROVADO, true).build());
    }

    /** Último certificado da cadeia montada pelo DSS (sem binários no relatório: casado pelo id) é âncora do acervo. */
    private boolean terminaNoAcervo(List<CertificateWrapper> chain, AcervoDeConfianca acervo) {
        if (chain.isEmpty()) {
            return false;
        }
        String rootId = chain.getLast().getId();
        return acervo.raizes().stream()
                .filter(raiz -> new CertificateToken(raiz).getDSSIdAsString().equals(rootId))
                .anyMatch(raiz -> verifiers.ehAncora(acervo, raiz));
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
