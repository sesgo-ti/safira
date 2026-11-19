/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.steps.trust.AcervoDeConfianca;
import br.gov.go.saude.fhir.safira.steps.trust.FonteDeConfianca;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HexFormat;
import java.util.List;
import java.util.Optional;

/**
 * {@link FonteDeConfianca} da PKI de simulação: acervo fixo, montado uma vez com as raízes e ACs
 * já conferidas. A geração é o SHA-256 do conteúdo (raízes e ACs, cada lista com contagem e cada
 * certificado com tamanho), estável entre reinícios e diferente para qualquer conteúdo diferente.
 */
public final class FonteDeConfiancaSimulada implements FonteDeConfianca {

    private final Optional<AcervoDeConfianca> acervo;

    public FonteDeConfiancaSimulada(List<X509Certificate> raizes, List<X509Certificate> intermediarias) {
        this.acervo = Optional.of(new AcervoDeConfianca("simulacao-" + digest(raizes, intermediarias),
                raizes, intermediarias));
    }

    @Override
    public Optional<AcervoDeConfianca> atual() {
        return acervo;
    }

    private static String digest(List<X509Certificate> raizes, List<X509Certificate> intermediarias) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            for (List<X509Certificate> lista : List.of(raizes, intermediarias)) {
                sha256.update(ByteBuffer.allocate(Integer.BYTES).putInt(lista.size()).array());
                for (X509Certificate certificado : lista) {
                    byte[] der = certificado.getEncoded();
                    sha256.update(ByteBuffer.allocate(Integer.BYTES).putInt(der.length).array());
                    sha256.update(der);
                }
            }
            return HexFormat.of().formatHex(sha256.digest());
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            throw new IllegalStateException("Falha ao calcular a geração do acervo simulado", e);
        }
    }
}
