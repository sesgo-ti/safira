/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/** Certificados públicos reais do acervo do ITI, para testes de regressão. */
public final class CertificadosIcpBrasilReais {

    private CertificadosIcpBrasilReais() {
    }

    /**
     * Raiz "Autoridade Certificadora Raiz Brasileira v7", assinada com o algoritmo
     * {@code 1.3.6.1.4.1.44588.2.1}, que o EU DSS não representa.
     */
    public static X509Certificate raizV7() {
        return carregar("/icpbrasil/ICP-Brasilv7.crt");
    }

    private static X509Certificate carregar(String recurso) {
        try (InputStream in = CertificadosIcpBrasilReais.class.getResourceAsStream(recurso)) {
            if (in == null) {
                throw new IllegalStateException("Recurso ausente: " + recurso);
            }
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(in);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (CertificateException e) {
            throw new IllegalStateException(e);
        }
    }
}
