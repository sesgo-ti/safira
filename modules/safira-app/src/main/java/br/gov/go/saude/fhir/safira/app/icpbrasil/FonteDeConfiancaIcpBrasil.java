/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.app.icpbrasil;

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
 * monotônico. Duas threads que vejam ao mesmo tempo a mesma instância nova podem numerá-la de
 * formas diferentes: é benigno, só faz o consumidor remontar as fontes mais uma vez.
 *
 * <p>Falha da lib, acervo sem raízes ou intermediárias ilegíveis viram vazio (fail-closed). A
 * primeira ocorrência de cada falha é registrada em ERROR; as repetições seguidas, em DEBUG.
 */
public final class FonteDeConfiancaIcpBrasil implements FonteDeConfianca {

    private static final Logger log = LoggerFactory.getLogger(FonteDeConfiancaIcpBrasil.class);

    private record Memo(TrustMaterial material, AcervoDeConfianca acervo) {
    }

    private final TrustMaterialSource source;
    private final AtomicLong geracoes = new AtomicLong();
    private final AtomicReference<Memo> memo = new AtomicReference<>();
    /** Última falha registrada em ERROR (instância do material ou descrição da exceção da lib). */
    private final AtomicReference<Object> ultimaFalha = new AtomicReference<>();

    public FonteDeConfiancaIcpBrasil(TrustMaterialSource source) {
        this.source = Objects.requireNonNull(source, "source");
    }

    @Override
    public Optional<AcervoDeConfianca> atual() {
        Optional<TrustMaterial> material;
        try {
            material = source.current();
        } catch (RuntimeException e) {
            String descricao = e.getClass().getName() + ": " + e.getMessage();
            return falha(descricao, "Acervo ICP-Brasil indisponível: falha da icpbrasil-truststore", e);
        }
        return material.isEmpty() ? Optional.empty() : acervo(material.get());
    }

    private Optional<AcervoDeConfianca> acervo(TrustMaterial material) {
        Memo vigente = memo.get();
        if (vigente != null && vigente.material() == material) {
            return sucesso(vigente.acervo());
        }
        List<X509Certificate> raizes = raizes(material);
        if (raizes.isEmpty()) {
            return falha(material, "Acervo ICP-Brasil sem raízes", null);
        }
        List<X509Certificate> intermediarias;
        try {
            intermediarias = intermediarias(material);
        } catch (CertStoreException | RuntimeException e) {
            return falha(material, "Acervo ICP-Brasil com intermediárias ilegíveis", e);
        }
        AcervoDeConfianca acervo = new AcervoDeConfianca(Long.toString(geracoes.incrementAndGet()),
                raizes, intermediarias);
        memo.compareAndSet(vigente, new Memo(material, acervo));
        return sucesso(acervo);
    }

    private Optional<AcervoDeConfianca> sucesso(AcervoDeConfianca acervo) {
        if (ultimaFalha.get() != null) {
            ultimaFalha.set(null);
        }
        return Optional.of(acervo);
    }

    private Optional<AcervoDeConfianca> falha(Object chave, String mensagem, Exception causa) {
        if (chave.equals(ultimaFalha.getAndSet(chave))) {
            log.debug(mensagem, causa);
        } else {
            log.error(mensagem, causa);
        }
        return Optional.empty();
    }

    private static List<X509Certificate> raizes(TrustMaterial material) {
        return material.anchors().stream().map(TrustAnchor::getTrustedCert).filter(Objects::nonNull).toList();
    }

    private static List<X509Certificate> intermediarias(TrustMaterial material) throws CertStoreException {
        return material.intermediates().getCertificates(null).stream()
                .filter(X509Certificate.class::isInstance)
                .map(X509Certificate.class::cast)
                .toList();
    }
}
