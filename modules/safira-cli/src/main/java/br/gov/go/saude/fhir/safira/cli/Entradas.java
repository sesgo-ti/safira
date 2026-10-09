/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.engine.config.SafiraOperationalConfigProperties;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.OperationOutcome;
import br.gov.go.saude.fhir.safira.engine.domain.fhir.SignatureExceptionCode;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJson;
import br.gov.go.saude.fhir.safira.engine.domain.json.LosslessJsonException;
import br.gov.go.saude.fhir.safira.rest.request.BoundedRequestBody;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Leitura dos arquivos de entrada com os limites da API: o Bundle até
 * {@code safira.operational.security.max-bundle-size} e o conjunto dos arquivos até o limite do corpo
 * de {@code /assinar} e {@code /validar} ({@link BoundedRequestBody#limit}). O tamanho é conferido antes
 * da leitura. Cada JSON precisa ser um único objeto (UTF-8, sem membros duplicados) antes de ser
 * embutido na requisição, o que impede injetar membros por um arquivo.
 */
final class Entradas {

    private static final long MAX_BUNDLE_SIZE_PADRAO = 52_428_800L;

    private final long limiteDoBundle;
    private final long limiteTotal;
    private long consumido;

    Entradas(SafiraOperationalConfigProperties operacional) {
        Integer maxBundleSize = operacional == null || operacional.security() == null
                ? null : operacional.security().maxBundleSize();
        this.limiteDoBundle = maxBundleSize != null ? maxBundleSize : MAX_BUNDLE_SIZE_PADRAO;
        this.limiteTotal = BoundedRequestBody.limit(operacional);
    }

    /** Bundle: objeto JSON até {@code max-bundle-size}. */
    String bundle(Path arquivo) {
        return objeto(arquivo, limiteDoBundle);
    }

    /** Demais recursos JSON (Provenance, Signature): objeto JSON dentro do limite total. */
    String objeto(Path arquivo) {
        return objeto(arquivo, limiteTotal);
    }

    /** Arquivo binário (PKCS#12) dentro do limite total. */
    byte[] binario(Path arquivo) {
        return ler(arquivo, limiteTotal);
    }

    private String objeto(Path arquivo, long limite) {
        String texto;
        try {
            texto = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(ler(arquivo, limite))).toString();
            LosslessJson.parseObject(texto);
        } catch (CharacterCodingException | LosslessJsonException e) {
            throw new FalhaDeUso("O arquivo " + arquivo + " não é um objeto JSON válido.",
                    outcome(SignatureExceptionCode.FORMAT_JSON_MALFORMED, "invalid", "O arquivo '" + arquivo.getFileName()
                            + "' não é um objeto JSON UTF-8 válido e sem membros duplicados."));
        }
        return texto;
    }

    private byte[] ler(Path arquivo, long limite) {
        if (!Files.isRegularFile(arquivo) || !Files.isReadable(arquivo)) {
            throw new FalhaDeUso("Arquivo não encontrado ou ilegível: " + arquivo);
        }
        try {
            long tamanho = Files.size(arquivo);
            if (tamanho > limite || consumido + tamanho > limiteTotal) {
                throw new FalhaDeUso("O arquivo " + arquivo + " excede o limite de tamanho.",
                        outcome(SignatureExceptionCode.SECURITY_BUNDLE_SIZE_LIMIT_EXCEEDED, "too-costly",
                                "A entrada excede o limite de " + Math.min(limite, limiteTotal - consumido)
                                        + " bytes ('" + arquivo.getFileName() + "', " + tamanho + " bytes)."));
            }
            consumido += tamanho;
            return Files.readAllBytes(arquivo);
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível ler " + arquivo + ": " + e.getMessage());
        }
    }

    static OperationOutcome outcome(SignatureExceptionCode codigo, String tipo, String diagnostico) {
        return OperationOutcome.createSignatureError(codigo.getSeverity() != null ? codigo.getSeverity() : "error",
                tipo, codigo.getCode(), codigo.getDisplay(), diagnostico);
    }
}
