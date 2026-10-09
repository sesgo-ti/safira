/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory.Acervo;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Verificadores do EU DSS sobre o acervo da {@link FonteDeConfianca}: raízes viram a fonte
 * confiável e intermediárias a adjunta; cadeia, revogação e validade ficam com o DSS.
 *
 * <p>Cada operação consulta a fonte uma única vez e recebe um verificador novo, preso àquela
 * geração. As fontes do DSS de uma geração são montadas uma vez, publicadas por troca atômica e
 * nunca alteradas; mudar a geração monta outras, sem afetar verificadores já entregues.
 */
public class VerificadoresDss {

    private record Geracao(String id, Acervo fontes) {
    }

    private final FonteDeConfianca fonte;
    private final CertificateVerifierFactory factory;
    private final AtomicReference<Geracao> geracao = new AtomicReference<>();

    public VerificadoresDss(FonteDeConfianca fonte, CertificateVerifierFactory factory) {
        this.fonte = Objects.requireNonNull(fonte, "fonte");
        this.factory = Objects.requireNonNull(factory, "factory");
    }

    /**
     * Verificador novo para uma operação; vazio quando o acervo está indisponível (fail-closed).
     *
     * @param ancorasExtras âncoras adicionais só desta operação (ex.: trust store TSA da política)
     */
    public Optional<CommonCertificateVerifier> paraOperacao(Collection<X509Certificate> ancorasExtras) {
        Objects.requireNonNull(ancorasExtras, "ancorasExtras");
        return fonte.atual().map(acervo -> factory.create(fontes(acervo), ancorasExtras));
    }

    private Acervo fontes(AcervoDeConfianca acervo) {
        Geracao vigente = geracao.get();
        if (vigente != null && vigente.id().equals(acervo.geracao())) {
            return vigente.fontes();
        }
        Geracao nova = new Geracao(acervo.geracao(),
                CertificateVerifierFactory.acervo(acervo.raizes(), acervo.intermediarias()));
        geracao.compareAndSet(vigente, nova);
        return nova.fontes();
    }
}
