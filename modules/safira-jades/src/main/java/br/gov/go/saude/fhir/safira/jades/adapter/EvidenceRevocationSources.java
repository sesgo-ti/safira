/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import eu.europa.esig.dss.spi.x509.revocation.ocsp.ExternalResourcesOCSPSource;

import java.util.List;

/**
 * Fontes de revogação <em>offline</em> construídas a partir de respostas OCSP e CRLs
 * completas em DER — insumo determinístico para a extensão B-LT ({@code rVals}).
 */
public final class EvidenceRevocationSources {

    private EvidenceRevocationSources() {
    }

    /**
     * @param ocspResponsesDer respostas OCSP completas (DER de {@code OCSPResponse}, RFC 6960)
     */
    public static RevocationSource<OCSP> ocspFromEvidence(List<byte[]> ocspResponsesDer) {
        if (ocspResponsesDer == null || ocspResponsesDer.isEmpty()) {
            return null;
        }
        return new ExternalResourcesOCSPSource(toDocuments(ocspResponsesDer));
    }

    /**
     * @param crlsDer CRLs completas (DER de {@code CertificateList}, RFC 5280)
     */
    public static RevocationSource<CRL> crlFromEvidence(List<byte[]> crlsDer) {
        if (crlsDer == null || crlsDer.isEmpty()) {
            return null;
        }
        return new ExternalResourcesCRLSource(toDocuments(crlsDer));
    }

    private static DSSDocument[] toDocuments(List<byte[]> derList) {
        return derList.stream()
                .map(InMemoryDocument::new)
                .toArray(DSSDocument[]::new);
    }
}
