/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.jades;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERSequence;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

/**
 * Conversão do valor de assinatura ECDSA entre as formas R||S (JWS, RFC 7515) e
 * DER/ASN.1 (JCA — {@code SEQUENCE { r INTEGER, s INTEGER }}).
 *
 * <p>O passo {@code crypto-signing} do Safira publica ES256 já transcodificado para
 * R||S (64 bytes). O DSS espera o formato JCA e faz a transcodificação inversa ao
 * montar o JWS; esta classe faz a ponte de forma determinística.
 */
public final class EcdsaSignatureFormats {

    private EcdsaSignatureFormats() {
    }

    /**
     * Converte R||S (concatenação de dois inteiros big-endian de mesmo tamanho) para DER.
     *
     * @param concatenated valor R||S (para P-256: 64 bytes)
     * @return {@code SEQUENCE { r INTEGER, s INTEGER }} em DER
     */
    public static byte[] concatToDer(byte[] concatenated) {
        if (concatenated == null || concatenated.length == 0 || concatenated.length % 2 != 0) {
            throw new IllegalArgumentException(
                    "Valor R||S inválido: esperado tamanho par, obtido "
                            + (concatenated == null ? "null" : concatenated.length));
        }
        int componentLength = concatenated.length / 2;
        BigInteger r = new BigInteger(1, Arrays.copyOfRange(concatenated, 0, componentLength));
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(concatenated, componentLength, concatenated.length));

        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));
        try {
            return new DERSequence(vector).getEncoded("DER");
        } catch (IOException e) {
            throw new IllegalStateException("Falha ao codificar assinatura ECDSA em DER", e);
        }
    }
}
