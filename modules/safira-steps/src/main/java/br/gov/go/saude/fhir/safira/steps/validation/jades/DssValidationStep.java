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
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties;
import br.gov.go.saude.fhir.safira.steps.policy.SafiraPolicyProperties.TsaPolicy;
import br.gov.go.saude.fhir.safira.steps.policy.TsaTrustStores;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenException;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector;
import br.gov.go.saude.fhir.safira.steps.timestamp.TimestampTokenInspector.Inspection;
import br.gov.go.saude.fhir.safira.steps.timestamp.TsaChainVerification;
import br.gov.go.saude.fhir.safira.steps.trust.IcpBrasilCertificateVerifiers;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.diagnostic.TimestampWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SignatureLevel;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.validation.reports.Reports;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * Passo {@code dss-validation}: o EU DSS decide a assinatura — verificação criptográfica JWS
 * (4.3), construção da cadeia (x5c, ACs do acervo e AIA), revogação OCSP/CRL obtida pelo próprio
 * DSS (6) e, em JAdES-B-T, o carimbo e a cadeia da TSA com prova de existência (5).
 *
 * <p>Âncoras: raízes do acervo ICP-Brasil e, em B-T, as do trust store TSA da política, cuja
 * cadeia do carimbo precisa terminar numa delas. Tempo: em B-B o DSS valida no instante atual
 * (certificado revogado agora → {@code REVOKED_NO_POE} → {@code CERT.REVOKED}); em B-T o carimbo
 * é a POE e revogação posterior a ele não invalida a assinatura.
 *
 * <p>Política de validação: a padrão do DSS 6.4 (ETSI EN 319 102-1). As regras específicas da
 * SES-GO (OIDs ICP-Brasil, keyUsage, identidade, janela do carimbo) ficam nos passos próprios;
 * uma política XML versionada só se justifica se a padrão divergir do IG.
 */
// DIVERGENCIA-IG D7: validade histórica (intervalo I) em B-T decidida pelo DSS com o carimbo como POE
@StepId("dss-validation")
public class DssValidationStep implements ValidationStep {

    private final IcpBrasilCertificateVerifiers verifiers;
    private final SafiraPolicyProperties policy;
    private final JadesValidationService validationService = new JadesValidationService();

    public DssValidationStep(IcpBrasilCertificateVerifiers verifiers, SafiraPolicyProperties policy) {
        this.verifiers = verifiers;
        this.policy = policy;
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

        Optional<CommonCertificateVerifier> verifier = verifiers.current(tsaAnchors);
        if (verifier.isEmpty()) {
            return fail(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY, "Acervo ICP-Brasil indisponível.", context);
        }
        Reports reports = validationService.validate(jws, verifier.get());
        SimpleReport report = reports.getSimpleReport();
        String id = report.getFirstSignatureId();

        if (level == JadesLevel.B_T) {
            Optional<StepResult<ValidationContext>> timestampFailure =
                    verifyTimestamp(reports, id, tsaAnchors, tsaPolicy, context);
            if (timestampFailure.isPresent()) {
                return timestampFailure.get();
            }
        }

        Indication indication = report.getIndication(id);
        if (indication != Indication.TOTAL_PASSED) {
            SubIndication sub = report.getSubIndication(id);
            SignatureExceptionCode code = sub == SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE
                    && missingRevocation(reports.getDiagnosticData().getSignatureById(id).getCertificateChain())
                    ? SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN
                    : codeFor(indication, sub);
            return fail(code, "EU DSS: " + indication + (sub == null ? "" : "/" + sub)
                    + " " + messages(report.getAdESValidationErrors(id)), context);
        }
        SignatureLevel expected = level == JadesLevel.B_B ? SignatureLevel.JAdES_BASELINE_B : SignatureLevel.JAdES_BASELINE_T;
        if (report.getSignatureFormat(id) != expected) {
            return fail(SignatureExceptionCode.VALIDATION_JADES_LEVEL_INVALID,
                    "EU DSS classificou a assinatura como " + report.getSignatureFormat(id) + "; esperado " + expected + ".",
                    context);
        }
        return StepResult.success(getName(), context);
    }

    /**
     * O carimbo da assinatura precisa ser {@code PASSED} no DSS e sua cadeia, montada pelo DSS,
     * precisa terminar numa âncora do trust store TSA da política (não basta uma raiz do acervo).
     */
    private Optional<StepResult<ValidationContext>> verifyTimestamp(Reports reports, String signatureId,
                                                                    List<X509Certificate> tsaAnchors,
                                                                    TsaPolicy tsaPolicy, ValidationContext context) {
        SimpleReport report = reports.getSimpleReport();
        List<XmlTimestamp> timestamps = report.getSignatureTimestamps(signatureId);
        if (timestamps.size() != 1) {
            return Optional.of(fail(SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "EU DSS identificou " + timestamps.size() + " carimbos de assinatura; esperado 1.", context));
        }
        String timestampId = timestamps.getFirst().getId();
        Indication indication = report.getIndication(timestampId);
        TimestampWrapper wrapper = reports.getDiagnosticData().getTimestampById(timestampId);
        List<CertificateWrapper> chain = wrapper.getCertificateChain();
        if (indication != Indication.PASSED) {
            SubIndication sub = report.getSubIndication(timestampId);
            SignatureExceptionCode code = sub == SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE && missingRevocation(chain)
                    ? SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN
                    : timestampCodeFor(sub);
            return Optional.of(fail(code, "EU DSS (carimbo): " + indication
                    + (sub == null ? "" : "/" + sub) + " " + messages(report.getAdESValidationErrors(timestampId)), context));
        }
        if (chain.isEmpty() || !isAnchor(chain.getLast(), tsaAnchors)) {
            return Optional.of(fail(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED,
                    "A cadeia da TSA não termina em âncora do trust store da política " + tsaPolicy.oid() + ".", context));
        }
        return Optional.empty();
    }

    private static boolean isAnchor(CertificateWrapper certificate, List<X509Certificate> anchors) {
        return anchors.stream().anyMatch(anchor -> new CertificateToken(anchor).getDSSIdAsString().equals(certificate.getId()));
    }

    /**
     * Algum certificado não confiável da cadeia ficou sem dado de revogação — o DSS reporta
     * {@code CERTIFICATE_CHAIN_GENERAL_FAILURE} (OCSP/CRL inalcançáveis ou ausentes).
     */
    private static boolean missingRevocation(List<CertificateWrapper> chain) {
        return chain.stream()
                .filter(certificate -> !certificate.isTrusted())
                .anyMatch(certificate -> certificate.getCertificateRevocationData().isEmpty());
    }

    private static List<String> messages(List<Message> messages) {
        return messages.stream().map(Message::getValue).toList();
    }

    private static SignatureExceptionCode timestampCodeFor(SubIndication sub) {
        if (sub == null) {
            return SignatureExceptionCode.TSA_VALIDATION_FAILED;
        }
        return switch (sub) {
            case HASH_FAILURE -> SignatureExceptionCode.TSA_MESSAGE_IMPRINT_MISMATCH;
            case SIG_CRYPTO_FAILURE -> SignatureExceptionCode.TSA_SIGNATURE_INVALID;
            case REVOKED, REVOKED_NO_POE, REVOKED_CA_NO_POE -> SignatureExceptionCode.TSA_CERTIFICATE_REVOKED;
            case EXPIRED, NOT_YET_VALID, OUT_OF_BOUNDS_NO_POE, OUT_OF_BOUNDS_NOT_REVOKED ->
                    SignatureExceptionCode.TSA_CERTIFICATE_TIME_INVALID;
            case TRY_LATER, REVOCATION_OUT_OF_BOUNDS_NO_POE -> SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN;
            case NO_CERTIFICATE_CHAIN_FOUND, NO_CERTIFICATE_CHAIN_FOUND_NO_POE, CHAIN_CONSTRAINTS_FAILURE ->
                    SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED;
            default -> SignatureExceptionCode.TSA_VALIDATION_FAILED;
        };
    }

    private static SignatureExceptionCode codeFor(Indication indication, SubIndication sub) {
        if (sub == null) {
            return indication == Indication.INDETERMINATE
                    ? SignatureExceptionCode.VALIDATION_INDETERMINATE
                    : SignatureExceptionCode.VALIDATION_POLICY_COMPLIANCE_FAILED;
        }
        return switch (sub) {
            case SIG_CRYPTO_FAILURE, HASH_FAILURE -> SignatureExceptionCode.VALIDATION_SIGNATURE_VERIFICATION_FAILED;
            case CHAIN_CONSTRAINTS_FAILURE -> SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED;
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
