/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.policy;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Resolve {@code tsaPolicies.policies[].trustStore.reference}: bundle PEM (ou DER) com as
 * âncoras de uma política TSA, separado do acervo ICP-Brasil do signatário.
 *
 * <p>Formatos da referência: {@code classpath:<recurso>}, {@code file:<caminho>} ou caminho
 * simples no sistema de arquivos.
 */
// DIVERGENCIA-IG D4: o IG não define o formato de trustStore.reference; adotado bundle PEM
public final class TsaTrustStores {

    private static final String CLASSPATH = "classpath:";
    private static final String FILE = "file:";

    private TsaTrustStores() {
    }

    /**
     * @throws IllegalArgumentException referência ausente, ilegível ou sem certificados
     */
    public static List<X509Certificate> load(String reference) {
        if (reference == null || reference.isBlank()) {
            throw new IllegalArgumentException("Referência de trust store TSA ausente");
        }
        try (InputStream in = open(reference)) {
            Collection<? extends Certificate> parsed = CertificateFactory.getInstance("X.509")
                    .generateCertificates(in);
            List<X509Certificate> anchors = new ArrayList<>();
            for (Certificate certificate : parsed) {
                anchors.add((X509Certificate) certificate);
            }
            if (anchors.isEmpty()) {
                throw new IllegalArgumentException("Trust store TSA sem certificados: " + reference);
            }
            return List.copyOf(anchors);
        } catch (IOException | CertificateException e) {
            throw new IllegalArgumentException("Trust store TSA ilegível: " + reference + " (" + e.getMessage() + ")", e);
        }
    }

    private static InputStream open(String reference) throws IOException {
        if (reference.startsWith(CLASSPATH)) {
            String resource = reference.substring(CLASSPATH.length()).replaceFirst("^/", "");
            InputStream in = Thread.currentThread().getContextClassLoader().getResourceAsStream(resource);
            if (in == null) {
                throw new IOException("recurso não encontrado no classpath");
            }
            return in;
        }
        String path = reference.startsWith(FILE) ? reference.substring(FILE.length()) : reference;
        return Files.newInputStream(Path.of(path));
    }
}
