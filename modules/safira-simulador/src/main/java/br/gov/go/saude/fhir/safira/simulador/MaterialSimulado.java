/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import org.springframework.core.io.Resource;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

/** Carrega e confere as raízes e ACs da PKI de simulação; qualquer problema impede o startup. */
final class MaterialSimulado {

    private MaterialSimulado() {
    }

    static TrustMaterial carregar(SafiraSimulacaoProperties propriedades) {
        if (propriedades.trustAnchors() == null) {
            throw new IllegalStateException("Modo simulação ligado sem safira.simulacao.trust-anchors "
                    + "(SAFIRA_SIMULACAO_TRUST_ANCHORS): informe o bundle PEM com as raízes da PKI simulada.");
        }
        List<X509Certificate> raizes = certificados(propriedades.trustAnchors(), "safira.simulacao.trust-anchors");
        for (X509Certificate raiz : raizes) {
            if (!autoassinado(raiz) || raiz.getBasicConstraints() < 0) {
                throw new IllegalStateException("safira.simulacao.trust-anchors: " + nome(raiz)
                        + " não é AC raiz autoassinada (BasicConstraints cA=true).");
            }
            // Marca obrigatória no titular: impede que uma raiz ICP-Brasil real (ou sósia) vire âncora simulada.
            if (!nome(raiz).contains(GeradorPkiSimulada.MARCA)) {
                throw new IllegalStateException("safira.simulacao.trust-anchors: " + nome(raiz)
                        + " não contém a marca '" + GeradorPkiSimulada.MARCA + "' no titular.");
            }
            if (!chaveForte(raiz.getPublicKey())) {
                throw new IllegalStateException("safira.simulacao.trust-anchors: " + nome(raiz)
                        + " tem chave fraca ou não suportada (exigido RSA >= 2048 ou EC >= 256 bits).");
            }
            try {
                raiz.checkValidity();
            } catch (CertificateException e) {
                throw new IllegalStateException("safira.simulacao.trust-anchors: " + nome(raiz)
                        + " está fora do período de validade.", e);
            }
        }
        List<X509Certificate> acs = propriedades.intermediates() == null ? List.of()
                : certificados(propriedades.intermediates(), "safira.simulacao.intermediates");
        for (X509Certificate ac : acs) {
            if (autoassinado(ac) || ac.getBasicConstraints() < 0) {
                throw new IllegalStateException("safira.simulacao.intermediates: " + nome(ac)
                        + " deve ser AC intermediária (cA=true, não autoassinada); raízes vão em trust-anchors.");
            }
        }
        List<X509Certificate> todos = new ArrayList<>(raizes);
        todos.addAll(acs);
        TrustMaterial material = TrustMaterial.of(todos);
        if (material.anchors().size() != raizes.size()) {
            throw new IllegalStateException("safira.simulacao.trust-anchors: nem todas as raízes foram aceitas como âncora.");
        }
        return material;
    }

    private static List<X509Certificate> certificados(Resource recurso, String propriedade) {
        RecursoLocal.exigir(recurso, propriedade);
        if (!recurso.exists() || !recurso.isReadable()) {
            throw new IllegalStateException(propriedade + ": arquivo não encontrado ou ilegível: " + recurso.getDescription());
        }
        try (InputStream in = recurso.getInputStream()) {
            List<X509Certificate> certificados = CertificateFactory.getInstance("X.509").generateCertificates(in).stream()
                    .map(X509Certificate.class::cast)
                    .toList();
            if (certificados.isEmpty()) {
                throw new IllegalStateException(propriedade + ": nenhum certificado em " + recurso.getDescription());
            }
            return certificados;
        } catch (IOException | CertificateException e) {
            throw new IllegalStateException(propriedade + ": PEM ilegível em " + recurso.getDescription(), e);
        }
    }

    private static boolean autoassinado(X509Certificate certificado) {
        if (!certificado.getSubjectX500Principal().equals(certificado.getIssuerX500Principal())) {
            return false;
        }
        try {
            certificado.verify(certificado.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    private static boolean chaveForte(PublicKey chave) {
        return switch (chave) {
            case RSAPublicKey rsa -> rsa.getModulus().bitLength() >= 2048;
            case ECPublicKey ec -> ec.getParams().getOrder().bitLength() >= 256;
            default -> false;
        };
    }

    private static String nome(X509Certificate certificado) {
        return certificado.getSubjectX500Principal().getName();
    }
}
