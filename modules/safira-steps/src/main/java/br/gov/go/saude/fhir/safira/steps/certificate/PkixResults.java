/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;

import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.PKIXReason;
import java.util.Optional;

/**
 * Traduz o {@link ValidationResult} do {@code PkixCertificateValidator} (lib
 * icpbrasil-truststore) para os códigos do CodeSystem da política 0.2.0.
 */
public final class PkixResults {

    private PkixResults() {
    }

    /** Vazio somente para {@link ValidationResult.Valid}; inconclusivo nunca vira sucesso. */
    public static Optional<PolicyViolation> violation(ValidationResult result) {
        return switch (result) {
            case ValidationResult.Valid ignored -> Optional.empty();
            case ValidationResult.Untrusted untrusted -> Optional.of(untrusted(untrusted));
            case ValidationResult.Revoked revoked -> Optional.of(new PolicyViolation(SignatureExceptionCode.CERT_REVOKED,
                    "Certificado revogado: " + revoked.certificate().getSubjectX500Principal().getName()
                            + (revoked.revokedAt() == null ? "" : " em " + revoked.revokedAt())
                            + " (motivo " + revoked.reason() + ")."));
            case ValidationResult.RevocationUndetermined undetermined -> Optional.of(undetermined(undetermined));
            case ValidationResult.TrustStoreUnavailable ignored -> Optional.of(new PolicyViolation(
                    SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY,
                    "Acervo ICP-Brasil indisponível ou expirado: nenhuma âncora de confiança carregada."));
        };
    }

    private static PolicyViolation untrusted(ValidationResult.Untrusted untrusted) {
        String detail = "Validação PKIX (RFC 5280) falhou: " + untrusted.detail();
        if (untrusted.reason() == BasicReason.EXPIRED) {
            return new PolicyViolation(SignatureExceptionCode.CERT_EXPIRED, detail);
        }
        if (untrusted.reason() == BasicReason.NOT_YET_VALID) {
            return new PolicyViolation(SignatureExceptionCode.CERT_NOT_YET_VALID, detail);
        }
        if (untrusted.reason() == PKIXReason.NO_TRUST_ANCHOR) {
            return new PolicyViolation(SignatureExceptionCode.CERT_NOT_ICP_BRASIL, detail);
        }
        return new PolicyViolation(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED, detail);
    }

    // DIVERGENCIA-IG D10: a lib não distingue OCSP 'unknown' de outras respostas inconclusivas
    private static PolicyViolation undetermined(ValidationResult.RevocationUndetermined undetermined) {
        String subject = undetermined.certificate().getSubjectX500Principal().getName();
        return new PolicyViolation(revocationCode(undetermined.status()), "Estado de revogação inconclusivo para "
                + subject + ": " + undetermined.status().getClass().getSimpleName() + ".");
    }

    /** Código do CodeSystem para um status de revogação inconclusivo da lib. */
    public static SignatureExceptionCode revocationCode(RevocationStatus status) {
        return switch (status) {
            case RevocationStatus.NoDistributionPoints ignored -> SignatureExceptionCode.REVOCATION_NO_DISTRIBUTION_POINTS;
            case RevocationStatus.OcspUnavailable ignored -> SignatureExceptionCode.REVOCATION_OCSP_UNAVAILABLE;
            case RevocationStatus.CrlUnavailable ignored -> SignatureExceptionCode.REVOCATION_CRL_UNAVAILABLE;
            case RevocationStatus.NoConnectivity ignored -> SignatureExceptionCode.REVOCATION_NO_CONNECTIVITY;
            case RevocationStatus.Malformed ignored -> SignatureExceptionCode.REVOCATION_RESPONSE_MALFORMED;
            case RevocationStatus.Good ignored -> SignatureExceptionCode.REVOCATION_STATUS_UNKNOWN;
            case RevocationStatus.Revoked ignored -> SignatureExceptionCode.CERT_REVOKED;
        };
    }
}
