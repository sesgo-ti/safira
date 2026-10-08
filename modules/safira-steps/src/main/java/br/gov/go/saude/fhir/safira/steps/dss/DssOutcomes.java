/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.dss;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import eu.europa.esig.dss.diagnostic.CertificateWrapper;
import eu.europa.esig.dss.enumerations.Indication;
import eu.europa.esig.dss.enumerations.SubIndication;
import eu.europa.esig.dss.jaxb.object.Message;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.simplereport.SimpleReport;
import eu.europa.esig.dss.simplereport.jaxb.XmlTimestamp;
import eu.europa.esig.dss.validation.reports.Reports;

import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Traduz os resultados do EU DSS ({@code Indication}/{@code SubIndication} e dados de diagnóstico)
 * para os códigos do CodeSystem da política 0.2.0 — comum à validação e à assinatura.
 */
public final class DssOutcomes {

    private static final Set<SubIndication> REVOKED =
            EnumSet.of(SubIndication.REVOKED, SubIndication.REVOKED_NO_POE, SubIndication.REVOKED_CA_NO_POE);

    private DssOutcomes() {
    }

    /**
     * Código para uma assinatura ou certificado que não passou na validação do DSS.
     *
     * @param chain          cadeia montada pelo DSS (certificado do signatário primeiro)
     * @param validationTime instante da validação do DSS; folha com {@code notAfter} anterior a ele
     *                       resulta em {@code CERT.EXPIRED} (salvo revogação, que prevalece)
     */
    public static SignatureExceptionCode code(Indication indication, SubIndication sub, List<CertificateWrapper> chain,
                                              Date validationTime) {
        if (!REVOKED.contains(sub) && !chain.isEmpty() && validationTime != null
                && chain.getFirst().getNotAfter().before(validationTime)) {
            return SignatureExceptionCode.CERT_EXPIRED;
        }
        if (sub == SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE && missingRevocation(chain)) {
            return SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN;
        }
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

    /**
     * O carimbo da assinatura precisa ser {@code PASSED} no DSS e sua cadeia, montada pelo DSS,
     * precisa terminar numa âncora do trust store TSA da política (não basta uma raiz do acervo).
     */
    public static Optional<PolicyViolation> signatureTimestamp(Reports reports, String signatureId,
                                                               List<X509Certificate> tsaAnchors, String tsaPolicyOid) {
        List<XmlTimestamp> timestamps = reports.getSimpleReport().getSignatureTimestamps(signatureId);
        if (timestamps.size() != 1) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_INVALID_TOKEN,
                    "EU DSS identificou " + timestamps.size() + " carimbos de assinatura; esperado 1."));
        }
        return timestamp(reports, timestamps.getFirst().getId(), tsaAnchors, tsaPolicyOid);
    }

    /**
     * Mesmo critério para um carimbo identificado — também o token avulso validado pelo
     * {@code DetachedTimestampValidator}.
     */
    public static Optional<PolicyViolation> timestamp(Reports reports, String timestampId,
                                                      List<X509Certificate> tsaAnchors, String tsaPolicyOid) {
        SimpleReport report = reports.getSimpleReport();
        Indication indication = report.getIndication(timestampId);
        List<CertificateWrapper> chain = reports.getDiagnosticData().getTimestampById(timestampId).getCertificateChain();
        if (indication != Indication.PASSED) {
            SubIndication sub = report.getSubIndication(timestampId);
            SignatureExceptionCode code = sub == SubIndication.CERTIFICATE_CHAIN_GENERAL_FAILURE && missingRevocation(chain)
                    ? SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN
                    : timestampCode(sub);
            return Optional.of(new PolicyViolation(code, "EU DSS (carimbo): " + indication
                    + (sub == null ? "" : "/" + sub) + " " + messages(report.getAdESValidationErrors(timestampId))));
        }
        if (chain.isEmpty() || !isAnchor(chain.getLast(), tsaAnchors)) {
            return Optional.of(new PolicyViolation(SignatureExceptionCode.TSA_CHAIN_VALIDATION_FAILED,
                    "A cadeia da TSA não termina em âncora do trust store da política " + tsaPolicyOid + "."));
        }
        return Optional.empty();
    }

    public static List<String> messages(List<Message> messages) {
        return messages.stream().map(Message::getValue).toList();
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

    private static SignatureExceptionCode timestampCode(SubIndication sub) {
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
}
