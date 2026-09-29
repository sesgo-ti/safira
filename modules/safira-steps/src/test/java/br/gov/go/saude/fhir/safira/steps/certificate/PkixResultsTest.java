/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.certificate;

import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.jades.fixture.TestPki;
import br.gov.go.saude.fhir.safira.steps.policy.PolicyViolation;
import br.gov.go.saude.truststore.icpbrasil.model.RevocationStatus;
import br.gov.go.saude.truststore.icpbrasil.model.ValidationResult;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.security.cert.CRLReason;
import java.security.cert.CertPathValidatorException.BasicReason;
import java.security.cert.PKIXReason;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class PkixResultsTest {

    private static TestPki pki;

    @BeforeAll
    static void createPki() {
        pki = TestPki.create();
    }

    private static Optional<SignatureExceptionCode> code(ValidationResult result) {
        return PkixResults.violation(result).map(PolicyViolation::code);
    }

    @Test
    void shouldAcceptValidResult() {
        assertThat(code(new ValidationResult.Valid(List.of(pki.leafCert), pki.caCert, List.of()))).isEmpty();
    }

    @Test
    void shouldMapExpiredPath() {
        assertThat(code(new ValidationResult.Untrusted(BasicReason.EXPIRED, "x")))
                .contains(SignatureExceptionCode.CERT_EXPIRED);
    }

    @Test
    void shouldMapNotYetValidPath() {
        assertThat(code(new ValidationResult.Untrusted(BasicReason.NOT_YET_VALID, "x")))
                .contains(SignatureExceptionCode.CERT_NOT_YET_VALID);
    }

    @Test
    void shouldMapMissingTrustAnchorToNotIcpBrasil() {
        assertThat(code(new ValidationResult.Untrusted(PKIXReason.NO_TRUST_ANCHOR, "x")))
                .contains(SignatureExceptionCode.CERT_NOT_ICP_BRASIL);
    }

    @Test
    void shouldMapOtherPkixFailuresToChainValidationFailed() {
        assertThat(code(new ValidationResult.Untrusted(PKIXReason.INVALID_KEY_USAGE, "x")))
                .contains(SignatureExceptionCode.CERT_CHAIN_VALIDATION_FAILED);
    }

    @Test
    void shouldMapRevokedCertificate() {
        assertThat(code(new ValidationResult.Revoked(pki.leafCert, Instant.EPOCH, CRLReason.KEY_COMPROMISE, null)))
                .contains(SignatureExceptionCode.CERT_REVOKED);
    }

    @Test
    void shouldMapEachUndeterminedRevocationStatus() {
        assertThat(code(undetermined(new RevocationStatus.NoDistributionPoints())))
                .contains(SignatureExceptionCode.REVOCATION_NO_DISTRIBUTION_POINTS);
        assertThat(code(undetermined(new RevocationStatus.OcspUnavailable())))
                .contains(SignatureExceptionCode.REVOCATION_OCSP_UNAVAILABLE);
        assertThat(code(undetermined(new RevocationStatus.CrlUnavailable())))
                .contains(SignatureExceptionCode.REVOCATION_CRL_UNAVAILABLE);
        assertThat(code(undetermined(new RevocationStatus.NoConnectivity())))
                .contains(SignatureExceptionCode.REVOCATION_NO_CONNECTIVITY);
        assertThat(code(undetermined(new RevocationStatus.Malformed("OCSP"))))
                .contains(SignatureExceptionCode.REVOCATION_RESPONSE_MALFORMED);
    }

    @Test
    void shouldMapUnavailableTrustStore() {
        assertThat(code(new ValidationResult.TrustStoreUnavailable()))
                .contains(SignatureExceptionCode.CONFIG_TRUST_STORE_EMPTY);
    }

    private static ValidationResult undetermined(RevocationStatus status) {
        return new ValidationResult.RevocationUndetermined(pki.leafCert, status);
    }
}
