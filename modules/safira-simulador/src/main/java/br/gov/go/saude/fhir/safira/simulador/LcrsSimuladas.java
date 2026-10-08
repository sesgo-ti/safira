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
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.List;

/** LCRs locais (DER ou PEM) da PKI de simulação como fonte offline de revogação do DSS. */
final class LcrsSimuladas {

    private LcrsSimuladas() {
    }

    static ExternalResourcesCRLSource fonte(List<Resource> lcrs) {
        return new ExternalResourcesCRLSource(lcrs.stream().map(LcrsSimuladas::documento).toArray(DSSDocument[]::new));
    }

    private static DSSDocument documento(Resource recurso) {
        if (!recurso.exists() || !recurso.isReadable()) {
            throw new IllegalStateException("safira.simulacao.crls: arquivo não encontrado ou ilegível: "
                    + recurso.getDescription());
        }
        try (InputStream in = recurso.getInputStream()) {
            byte[] der = ((X509CRL) CertificateFactory.getInstance("X.509").generateCRL(in)).getEncoded();
            return new InMemoryDocument(der, recurso.getFilename());
        } catch (IOException | CertificateException | CRLException | RuntimeException e) {
            throw new IllegalStateException("safira.simulacao.crls: LCR ilegível em " + recurso.getDescription(), e);
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
