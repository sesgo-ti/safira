/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust;

import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory;
import br.gov.go.saude.fhir.safira.jades.adapter.CertificateVerifierFactory.Acervo;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import eu.europa.esig.dss.spi.validation.CommonCertificateVerifier;

import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Verificador do EU DSS alimentado pelo acervo ICP-Brasil vigente. A lib icpbrasil-truststore
 * atua só como carregadora de certificados — raízes ({@link TrustMaterial#anchors()}) viram
 * confiáveis e ACs ({@link TrustMaterial#intermediates()}) viram adjuntas; cadeia, AIA, revogação
 * e validade ficam com o DSS.
 *
 * <p>As fontes do DSS são reaproveitadas enquanto o acervo não muda de geração (identidade do
 * {@link TrustMaterial} devolvido pela lib); cada chamada recebe um verificador novo, com as
 * âncoras extras dela.
 */
public class IcpBrasilCertificateVerifiers {

    private record Generation(TrustMaterial material, Acervo acervo) {
    }

    private final TrustMaterialSource trustMaterialSource;
    private final CertificateVerifierFactory factory;
    private volatile Generation generation;

    public IcpBrasilCertificateVerifiers(TrustMaterialSource trustMaterialSource, CertificateVerifierFactory factory) {
        this.trustMaterialSource = Objects.requireNonNull(trustMaterialSource, "trustMaterialSource");
        this.factory = Objects.requireNonNull(factory, "factory");
    }

    /** Verificador sobre o acervo vigente; vazio quando a lib não tem acervo utilizável (fail-closed). */
    public Optional<CommonCertificateVerifier> current() {
        return current(List.of());
    }

    /**
     * @param extraTrusted âncoras adicionais desta chamada (ex.: trust store TSA da política)
     */
    public Optional<CommonCertificateVerifier> current(Collection<X509Certificate> extraTrusted) {
        return trustMaterialSource.current().map(material -> factory.create(acervo(material), extraTrusted));
    }

    private Acervo acervo(TrustMaterial material) {
        Generation current = generation;
        if (current == null || current.material() != material) {
            current = new Generation(material, CertificateVerifierFactory.acervo(roots(material), cas(material)));
            generation = current;
        }
        return current.acervo();
    }

    private static List<X509Certificate> roots(TrustMaterial material) {
        return material.anchors().stream().map(TrustAnchor::getTrustedCert).toList();
    }

    private static List<X509Certificate> cas(TrustMaterial material) {
        try {
            Collection<? extends Certificate> certificates = material.intermediates().getCertificates(null);
            return certificates.stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();
        } catch (CertStoreException e) {
            throw new IllegalStateException("Acervo ICP-Brasil ilegível", e);
        }
    }
}
