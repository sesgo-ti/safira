/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.steps.trust.icpbrasil;

import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterial;
import br.gov.go.saude.truststore.icpbrasil.service.pkix.TrustMaterialSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.CertStoreException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * {@link FonteDeConfianca} sobre o acervo carregado pela icpbrasil-truststore: raízes vêm de
 * {@link TrustMaterial#anchors()} e intermediárias de {@link TrustMaterial#intermediates()}.
 *
 * <p>A lib memoiza um {@link TrustMaterial} por geração do acervo; enquanto ela devolver a mesma
 * instância, a geração não muda. Cada instância nova recebe o próximo valor de um contador
 * monotônico. Falha da lib, intermediárias ilegíveis ou acervo sem raízes viram vazio (fail-closed).
 */
public final class FonteDeConfiancaIcpBrasil implements FonteDeConfianca {

    private static final Logger log = LoggerFactory.getLogger(FonteDeConfiancaIcpBrasil.class);

    private record Memo(TrustMaterial material, AcervoDeConfianca acervo) {
    }

    private final TrustMaterialSource source;
    private final AtomicLong geracoes = new AtomicLong();
    private final AtomicReference<Memo> memo = new AtomicReference<>();

    public FonteDeConfiancaIcpBrasil(TrustMaterialSource source) {
        this.source = Objects.requireNonNull(source, "source");
    }

    @Override
    public Optional<AcervoDeConfianca> atual() {
        try {
            return source.current().map(this::acervo);
        } catch (RuntimeException e) {
            log.error("Acervo ICP-Brasil indisponível: {}", e.getMessage(), e);
            return Optional.empty();
        }
    }

    private AcervoDeConfianca acervo(TrustMaterial material) {
        Memo vigente = memo.get();
        if (vigente != null && vigente.material() == material) {
            return vigente.acervo();
        }
        AcervoDeConfianca acervo = new AcervoDeConfianca(Long.toString(geracoes.incrementAndGet()),
                raizes(material), intermediarias(material));
        memo.compareAndSet(vigente, new Memo(material, acervo));
        return acervo;
    }

    private static List<X509Certificate> raizes(TrustMaterial material) {
        return material.anchors().stream().map(TrustAnchor::getTrustedCert).toList();
    }

    private static List<X509Certificate> intermediarias(TrustMaterial material) {
        try {
            return material.intermediates().getCertificates(null).stream()
                    .filter(X509Certificate.class::isInstance)
                    .map(X509Certificate.class::cast)
                    .toList();
        } catch (CertStoreException e) {
            throw new IllegalStateException("Intermediárias do acervo ilegíveis", e);
        }
    }
}
