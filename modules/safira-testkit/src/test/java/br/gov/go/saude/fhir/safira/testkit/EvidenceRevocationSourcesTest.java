/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.enumerations.CertificateStatus;
import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class EvidenceRevocationSourcesTest {

    private static final PkiIcpSimulada PKI = PkiIcpSimulada.criar();

    @Test
    void shouldAnswerOcspPerCertificateFromResponder() {
        RevocationSource<OCSP> fonte = EvidenceRevocationSources.ocspPorCertificado(
                certificado -> certificado.equals(PKI.signatario()) ? PKI.ocspRevogado(certificado) : null);

        assertThat(fonte.getRevocationToken(new CertificateToken(PKI.signatario()), new CertificateToken(PKI.ac()))
                .getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(fonte.getRevocationToken(new CertificateToken(PKI.ac()), new CertificateToken(PKI.raiz()))).isNull();
    }

    @Test
    void shouldBuildSourcesFromDerEvidence() {
        assertThat(EvidenceRevocationSources.ocspFromEvidence(List.of(PKI.ocspBom(PKI.signatario())))
                .getRevocationToken(new CertificateToken(PKI.signatario()), new CertificateToken(PKI.ac()))
                .getStatus()).isEqualTo(CertificateStatus.GOOD);
        assertThat(EvidenceRevocationSources.crlFromEvidence(List.of(PKI.lcr()))
                .getRevocationToken(new CertificateToken(PKI.revogado()), new CertificateToken(PKI.ac()))
                .getStatus()).isEqualTo(CertificateStatus.REVOKED);
        assertThat(EvidenceRevocationSources.ocspFromEvidence(List.of())).isNull();
    }
}
