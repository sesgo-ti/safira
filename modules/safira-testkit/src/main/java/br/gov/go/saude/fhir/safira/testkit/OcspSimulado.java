/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.pki.exception.PKIException;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntity;
import eu.europa.esig.dss.pki.jaxb.model.JAXBCertEntityRepository;
import eu.europa.esig.dss.pki.model.CertEntityRevocation;
import eu.europa.esig.dss.pki.x509.revocation.ocsp.PKIOCSPSource;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.OCSPReq;

import java.io.IOException;
import java.util.Date;

/**
 * {@link PKIOCSPSource} da PKI simulada, com duas folgas sobre o original: responde sem URL de OCSP
 * no certificado (o XML não declara URLs) e responde {@code GOOD} a certificados emitidos pela AC
 * fora do repositório (cenários que montam certificados à mão). Com o status forçado, responde o
 * status informado ({@code null} = GOOD) para qualquer certificado consultado.
 */
final class OcspSimulado extends PKIOCSPSource {

    private final transient JAXBCertEntityRepository repositorio;
    private final boolean forcarStatus;
    private final transient CertEntityRevocation forcada;

    OcspSimulado(JAXBCertEntityRepository repositorio, boolean forcarStatus, CertEntityRevocation forcada,
                 Date proximaAtualizacao) {
        super(repositorio);
        this.repositorio = repositorio;
        this.forcarStatus = forcarStatus;
        this.forcada = forcada;
        setNextUpdate(proximaAtualizacao);
    }

    @Override
    protected boolean canGenerate(CertificateToken certificateToken, CertificateToken issuerCertificateToken) {
        return true;
    }

    @Override
    protected CertEntityRevocation getCertificateTokenRevocation(CertificateToken certificateToken, OCSPReq ocspReq) {
        if (forcarStatus) {
            return forcada;
        }
        JAXBCertEntity entidade = repositorio.getByCertificateToken(certificateToken);
        return entidade == null ? null : repositorio.getRevocation(entidade);
    }

    @Override
    protected void addRevocationStatusToOCSPResponse(BasicOCSPRespBuilder builder, OCSPReq ocspReq,
                                                     CertEntityRevocation certEntityRevocation) {
        super.addRevocationStatusToOCSPResponse(builder, ocspReq, certEntityRevocation);
        Extension nonce = ocspReq.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
        if (nonce != null) {
            builder.setResponseExtensions(new Extensions(nonce));
        }
    }

    /** Resposta (DER) a uma requisição OCSP recebida sobre {@code certificado}, emitido por {@code emissor}. */
    byte[] respostaDer(byte[] requisicaoDer, CertificateToken certificado, CertificateToken emissor) {
        try {
            return buildOCSPResponse(certificado, emissor, new OCSPReq(requisicaoDer)).getEncoded();
        } catch (IOException e) {
            throw new PKIException("Falha ao responder a requisição OCSP simulada", e);
        }
    }

    /** Resposta OCSP completa (DER de {@code OCSPResponse}). */
    byte[] respostaDer(CertificateToken certificado, CertificateToken emissor) {
        try {
            return buildOCSPResponse(certificado, emissor, buildOCSPRequest(certificado, emissor)).getEncoded();
        } catch (IOException e) {
            throw new PKIException("Falha ao codificar a resposta OCSP simulada", e);
        }
    }
}
