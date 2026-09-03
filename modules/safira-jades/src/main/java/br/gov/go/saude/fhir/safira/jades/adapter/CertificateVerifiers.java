/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.crl.CRL;
import eu.europa.esig.dss.model.x509.revocation.ocsp.OCSP;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;
import eu.europa.esig.dss.spi.x509.CommonTrustedCertificateSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;

import java.security.cert.X509Certificate;
import java.util.Collection;

/**
 * Fábrica de {@link CommonCertificateVerifier} para operações JAdES com ICP-Brasil.
 *
 * <p>As âncoras de confiança vêm do ecossistema já validado do Safira (a raiz da cadeia
 * aprovada pelo passo {@code chain-validation}, cuja confiabilidade foi confirmada no
 * trust-store ICP-Brasil) — o DSS não decide confiança sozinho.
 */
public final class CertificateVerifiers {

    private CertificateVerifiers() {
    }

    /**
     * Verificador com âncoras explícitas e fontes de revogação opcionais.
     *
     * @param trustAnchors certificados raiz confiáveis (ICP-Brasil)
     * @param ocspSource   fonte OCSP (evidências offline e/ou online); pode ser nula
     * @param crlSource    fonte CRL; pode ser nula
     */
    public static CommonCertificateVerifier create(
            Collection<X509Certificate> trustAnchors,
            RevocationSource<OCSP> ocspSource,
            RevocationSource<CRL> crlSource) {

        CommonCertificateVerifier verifier = new CommonCertificateVerifier();

        CommonTrustedCertificateSource trusted = new CommonTrustedCertificateSource();
        for (X509Certificate anchor : trustAnchors) {
            trusted.addCertificate(new CertificateToken(anchor));
        }
        verifier.setTrustedCertSources(trusted);

        if (ocspSource != null) {
            verifier.setOcspSource(ocspSource);
        }
        if (crlSource != null) {
            verifier.setCrlSource(crlSource);
        }
        return verifier;
    }
}
