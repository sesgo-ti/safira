/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.model.CertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.x509.revocation.crl.PKICRLSource;
import org.bouncycastle.operator.OperatorCreationException;

import java.io.IOException;
import java.util.Date;

/** {@link PKICRLSource} da PKI simulada: responde sem ponto de distribuição de LCR no certificado. */
final class LcrSimulada extends PKICRLSource {

    LcrSimulada(JAXBCertEntityRepository repositorio, Date proximaAtualizacao) {
        super(repositorio);
        setNextUpdate(proximaAtualizacao);
    }

    @Override
    protected boolean canGenerate(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        return true;
    }

    /** LCR (DER de {@code CertificateList}) emitida por {@code emissor}. */
    byte[] lcrDer(CertEntity emissor) {
        try {
            return generateCRL(emissor).getBinaries();
        } catch (IOException | OperatorCreationException e) {
            throw new PKIException("Falha ao gerar a LCR simulada", e);
        }
    }
}
