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
import br.gov.go.saude.fhir.safira.jades.StrictValidationPolicies;
import br.gov.go.saude.fhir.safira.steps.dss.DssOutcomes;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.AcceptedCertificatePolicy;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.VerificadoresDss;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

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
 * cadeia do carimbo precisa terminar numa delas. Tempo: em B-B o DSS valida no instante atual
 * (certificado revogado agora → {@code REVOKED_NO_POE} → {@code CERT.REVOKED}); em B-T o carimbo
 * é a POE e revogação posterior a ele não invalida a assinatura.
 *
 * <p>Política de validação: {@link StrictValidationPolicies} (versionada, derivada da padrão do
 * DSS 6.5) com a lista explícita dos OIDs da allowlist. As demais regras SES-GO (emissor da
 * allowlist, tipo, chave, keyUsage, identidade, janela do carimbo) ficam nos passos próprios; a
 * recusa por {@code PolicyIds} vira {@code VALIDATION.POLICY-COMPLIANCE-FAILED} (validar 4.1).
 */
// DIVERGENCIA-IG D7: validade histórica (intervalo I) em B-T decidida pelo DSS com o carimbo como POE
@StepId("dss-validation")
public class DssValidationStep implements ValidationStep {

    private final VerificadoresDss verifiers;
    private final SafiraPolicyProperties policy;
    private final JadesValidationService validationService;

    public DssValidationStep(VerificadoresDss verifiers, SafiraPolicyProperties policy) {
        this.verifiers = verifiers;
        this.policy = policy;
        this.validationService = new JadesValidationService(StrictValidationPolicies.comPoliticasAceitas(
                policy.acceptedCertificatePolicies().stream().map(AcceptedCertificatePolicy::oid).toList()));
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
                return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, e.getMessage(), context);
            }
        }

        Optional<AcervoDeConfianca> acervo = context.getAttribute(ValidationKeys.ACERVO, AcervoDeConfianca.class);
        if (acervo.isEmpty()) {
            return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, "Acervo ICP-Brasil indisponível.", context);
        }
        CommonCertificateVerifier verifier = verifiers.paraOperacao(acervo.get(), tsaAnchors);
        Reports reports = validationService.validate(jws, verifier);
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
            if (code == SignatureExceptionCode.CERT_NOT_ICP_BRASIL && DssOutcomes.policyIdsRejected(errors)) {
                code = SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
            }
            return fail(code, "EU DSS: " + indication + (sub == null ? "" : "/" + sub)
                    + " " + DssOutcomes.messages(errors), context);
        }
        SignatureLevel expected = level == JadesLevel.B_B ? SignatureLevel.JAdES_BASELINE_B : SignatureLevel.JAdES_BASELINE_T;
        if (report.getSignatureFormat(id) != expected) {
            return fail(SignatureExceptionCode.VALIDATION_JADES_LEVEL_INVALID,
                    "EU DSS classificou a assinatura como " + report.getSignatureFormat(id) + "; esperado " + expected + ".",
                    context);
        }
        return StepResult.success(getName(), context);
    }

    private StepResult<ValidationContext> fail(SignatureExceptionCode code, String diagnostics, ValidationContext context) {
        return StepResult.failure(getName(), code, diagnostics, context);
    }
}
