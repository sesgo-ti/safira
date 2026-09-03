/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades.adapter;

import eu.europa.esig.dss.model.x509.CertificateToken;
import eu.europa.esig.dss.model.x509.revocation.Revocation;
import eu.europa.esig.dss.spi.x509.revocation.RevocationSource;
import eu.europa.esig.dss.spi.x509.revocation.RevocationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Fonte de revogação composta: consulta os delegados em ordem e retorna o primeiro token
 * disponível. Usada na extensão B-LT para priorizar as <em>evidências já coletadas</em>
 * (offline, determinísticas) com <em>fallback online</em> (AIA/CDP) para certificados fora
 * da cadeia do signatário — tipicamente o certificado da TSA.
 */
public final class CompositeRevocationSource<R extends Revocation> implements RevocationSource<R> {

    private static final Logger log = LoggerFactory.getLogger(CompositeRevocationSource.class);

    private final transient List<RevocationSource<R>> delegates;

    private CompositeRevocationSource(List<RevocationSource<R>> delegates) {
        this.delegates = delegates;
    }

    /**
     * Compõe as fontes não-nulas na ordem informada; retorna {@code null} se todas forem nulas
     * e a própria fonte se houver apenas uma.
     */
    @SafeVarargs
    public static <R extends Revocation> RevocationSource<R> of(RevocationSource<R>... sources) {
        List<RevocationSource<R>> list = Arrays.stream(sources)
                .filter(Objects::nonNull)
                .toList();
        if (list.isEmpty()) {
            return null;
        }
        if (list.size() == 1) {
            return list.get(0);
        }
        return new CompositeRevocationSource<>(list);
    }

    @Override
    public RevocationToken<R> getRevocationToken(CertificateToken certificateToken, CertificateToken issuerToken) {
        for (RevocationSource<R> delegate : delegates) {
            try {
                RevocationToken<R> token = delegate.getRevocationToken(certificateToken, issuerToken);
                if (token != null) {
                    return token;
                }
            } catch (Exception e) {
                log.debug("Fonte de revogação {} falhou para {}: {}",
                        delegate.getClass().getSimpleName(), certificateToken.getDSSIdAsString(), e.getMessage());
            }
        }
        return null;
    }
}
