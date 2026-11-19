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
 * <p>Cada operação captura o acervo da fonte uma única vez ({@link #acervoAtual()}) e recebe
 * verificadores novos presos àquele snapshot. As fontes do DSS de uma geração são montadas uma
 * vez (certificados que o DSS não representa são ignorados com aviso nessa montagem), publicadas
 * por troca atômica e nunca alteradas; mudar a geração monta outras, sem afetar verificadores já entregues.
 */
public class VerificadoresDss {

    private record Geracao(String id, Acervo fontes) {
    }

    /**
     * O que o DSS usa da geração vigente.
     *
     * @param geracao        geração do acervo
     * @param raizes         raízes na fonte confiável do DSS
     * @param intermediarias ACs candidatas à cadeia
     * @param ignorados      certificados do acervo que o DSS não representa
     */
    public record Uso(String geracao, int raizes, int intermediarias, int ignorados) {
    }

    private final FonteDeConfianca fonte;
    private final CertificateVerifierFactory factory;
    private final AtomicReference<Geracao> geracao = new AtomicReference<>();

    public VerificadoresDss(FonteDeConfianca fonte, CertificateVerifierFactory factory) {
        this.fonte = Objects.requireNonNull(fonte, "fonte");
        this.factory = Objects.requireNonNull(factory, "factory");
    }

    /**
     * Acervo vigente da fonte; o chamador o guarda e o reusa durante toda a operação. Vazio também
     * quando nenhuma raiz da geração é representável pelo DSS (fail-closed).
     */
    public Optional<AcervoDeConfianca> acervoAtual() {
        return fonte.atual().filter(this::utilizavel);
    }

    /** Contagens do que o DSS usa do {@linkplain #acervoAtual() acervo vigente}; vazio quando indisponível. */
    public Optional<Uso> usoAtual() {
        return acervoAtual().map(acervo -> {
            Acervo fontes = fontes(acervo);
            return new Uso(acervo.geracao(), fontes.trusted().getCertificates().size(), fontes.cas().size(),
                    fontes.ignorados());
        });
    }

    /** Se ao menos uma raiz do snapshot é representável pelo DSS; sem ela, o acervo é indisponível. */
    public boolean utilizavel(AcervoDeConfianca acervo) {
        Objects.requireNonNull(acervo, "acervo");
        return fontes(acervo).utilizavel();
    }

    /**
     * Verificador novo preso ao snapshot informado, sem nova consulta à fonte; reaproveita as
     * fontes do DSS da mesma geração.
     *
     * @param acervo        snapshot capturado no início da operação
     * @param ancorasExtras âncoras adicionais só desta operação (ex.: trust store TSA da política)
     */
    public CommonCertificateVerifier paraOperacao(AcervoDeConfianca acervo, Collection<X509Certificate> ancorasExtras) {
        Objects.requireNonNull(acervo, "acervo");
        Objects.requireNonNull(ancorasExtras, "ancorasExtras");
        return factory.create(fontes(acervo), ancorasExtras);
    }

    /** Se o DSS considera o certificado uma âncora confiável da geração do snapshot informado. */
    public boolean ehAncora(AcervoDeConfianca acervo, X509Certificate certificado) {
        Objects.requireNonNull(acervo, "acervo");
        Objects.requireNonNull(certificado, "certificado");
        return CertificateVerifierFactory.token(certificado)
                .map(token -> fontes(acervo).trusted().isTrusted(token))
                .orElse(false);
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
