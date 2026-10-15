/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import eu.europa.esig.dss.model.DSSDocument;
import eu.europa.esig.dss.model.InMemoryDocument;
import eu.europa.esig.dss.spi.x509.revocation.crl.ExternalResourcesCRLSource;
import org.springframework.boot.autoconfigure.condition.ConditionOutcome;
import org.springframework.boot.autoconfigure.condition.SpringBootCondition;
import org.springframework.boot.context.properties.bind.Bindable;
import org.springframework.boot.context.properties.bind.Binder;
import org.springframework.context.annotation.ConditionContext;
import org.springframework.core.io.Resource;
import org.springframework.core.type.AnnotatedTypeMetadata;
import org.springframework.util.StringUtils;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

/** LCRs locais (DER ou PEM) da PKI de simulação como fonte offline de revogação do DSS. */
final class LcrsSimuladas {

    private LcrsSimuladas() {
    }

    /**
     * @param emissores raízes e ACs configuradas: cada LCR deve ser assinada por uma delas e ter
     *                  {@code nextUpdate} no futuro, senão o startup falha
     */
    static ExternalResourcesCRLSource fonte(List<Resource> lcrs, List<X509Certificate> emissores) {
        return new ExternalResourcesCRLSource(lcrs.stream().map(lcr -> documento(lcr, emissores))
                .toArray(DSSDocument[]::new));
    }

    private static DSSDocument documento(Resource recurso, List<X509Certificate> emissores) {
        RecursoLocal.exigir(recurso, "safira.simulacao.crls");
        if (!recurso.exists() || !recurso.isReadable()) {
            throw new IllegalStateException("safira.simulacao.crls: arquivo não encontrado ou ilegível: "
                    + recurso.getDescription());
        }
        X509CRL lcr;
        try (InputStream in = recurso.getInputStream()) {
            lcr = (X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in);
        } catch (IOException | CertificateException | CRLException | RuntimeException e) {
            throw new IllegalStateException("safira.simulacao.crls: LCR ilegível em " + recurso.getDescription(), e);
        }
        if (emissores.stream().noneMatch(emissor -> assinadaPor(lcr, emissor))) {
            throw new IllegalStateException("safira.simulacao.crls: LCR " + recurso.getDescription()
                    + " não é assinada por nenhuma raiz ou AC configurada (" + lcr.getIssuerX500Principal().getName() + ").");
        }
        if (lcr.getNextUpdate() == null || !lcr.getNextUpdate().after(new Date())) {
            throw new IllegalStateException("safira.simulacao.crls: LCR " + recurso.getDescription()
                    + " vencida ou sem nextUpdate (" + lcr.getNextUpdate() + ").");
        }
        try {
            return new InMemoryDocument(lcr.getEncoded(), recurso.getFilename());
        } catch (CRLException e) {
            throw new IllegalStateException("safira.simulacao.crls: LCR ilegível em " + recurso.getDescription(), e);
        }
    }

    private static boolean assinadaPor(X509CRL lcr, X509Certificate emissor) {
        if (!lcr.getIssuerX500Principal().equals(emissor.getSubjectX500Principal())) {
            return false;
        }
        try {
            lcr.verify(emissor.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    /** Verdadeira quando {@code safira.simulacao.crls} tem ao menos um item não vazio. */
    static final class Configuradas extends SpringBootCondition {

        @Override
        public ConditionOutcome getMatchOutcome(ConditionContext context, AnnotatedTypeMetadata metadata) {
            boolean presentes = Binder.get(context.getEnvironment())
                    .bind("safira.simulacao.crls", Bindable.listOf(String.class))
                    .map(lista -> lista.stream().anyMatch(StringUtils::hasText))
                    .orElse(false);
            return presentes ? ConditionOutcome.match("safira.simulacao.crls configurado")
                    : ConditionOutcome.noMatch("safira.simulacao.crls ausente");
        }
    }
}
