/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.testkit;

import org.bouncycastle.asn1.x509.KeyUsage;

import java.time.Period;

/**
 * Perfil do certificado do signatário da {@link PkiIcpSimulada}.
 *
 * <p>Política, keyUsage e chave entram no XML da PKI factory do DSS; DN, otherName ICP-Brasil e a
 * extensão crítica desconhecida (cenário de ataque) entram na reemissão pela AC.
 *
 * @param politica                    OID em certificatePolicies (nulo omite a extensão)
 * @param keyUsage                    bits de KeyUsage (constantes de {@link KeyUsage})
 * @param dn                          DN do titular
 * @param sanOid                      OID do otherName ICP-Brasil no SAN (nulo omite o SAN)
 * @param sanValor                    conteúdo do otherName
 * @param algoritmo                   {@code RSA} ou {@code EC}
 * @param bitsChave                   tamanho da chave (EC: 256)
 * @param extensaoCriticaDesconhecida acrescenta extensão crítica de OID desconhecido (RFC 5280 exige rejeitar)
 * @param validade                    validade a partir da criação (nulo = a do XML, 10 anos)
 */
public record PerfilSignatario(String politica, int keyUsage, String dn, String sanOid, String sanValor,
                               String algoritmo, int bitsChave, boolean extensaoCriticaDesconhecida,
                               Period validade) {

    /** OID do otherName ICP-Brasil com data de nascimento e CPF da pessoa física. */
    public static final String SAN_CPF = "2.16.76.1.3.1";
    /** OID do otherName ICP-Brasil com o CNPJ da pessoa jurídica. */
    public static final String SAN_CNPJ = "2.16.76.1.3.3";

    /** A3: RSA-2048, digitalSignature|nonRepudiation, CPF em SERIALNUMBER e no SAN. */
    public static PerfilSignatario a3() {
        return pessoaFisica("Fulano de Tal");
    }

    /** SE-S (selo): RSA-2048, digitalSignature, CNPJ em SERIALNUMBER e no SAN. */
    public static PerfilSignatario seS() {
        return new PerfilSignatario("2.16.76.1.2.201.1", KeyUsage.digitalSignature,
                dnSimulado("Estabelecimento Teste", PkiIcpSimulada.CNPJ),
                SAN_CNPJ, PkiIcpSimulada.CNPJ, "RSA", 2048, false, null);
    }

    static PerfilSignatario pessoaFisica(String nome) {
        return new PerfilSignatario("2.16.76.1.2.3.1", KeyUsage.digitalSignature | KeyUsage.nonRepudiation,
                dnSimulado(nome, PkiIcpSimulada.CPF),
                SAN_CPF, sanCpf(PkiIcpSimulada.CPF), "RSA", 2048, false, null);
    }

    /**
     * Conteúdo do otherName {@link #SAN_CPF} no formato do DOC-ICP-04: nascimento DDMMAAAA (8), CPF (11),
     * NIS (11), RG (15) e órgão expedidor/UF (6) — campos não informados com zeros.
     */
    public static String sanCpf(String cpf) {
        return "01011990" + cpf + "0".repeat(32);
    }

    private static String dnSimulado(String nome, String documento) {
        return "CN=" + nome + ":" + documento + ",SERIALNUMBER=" + documento
                + ",O=" + PkiIcpSimulada.MARCA + ",C=BR";
    }

    public PerfilSignatario comPolitica(String oid) {
        return new PerfilSignatario(oid, keyUsage, dn, sanOid, sanValor, algoritmo, bitsChave, extensaoCriticaDesconhecida, validade);
    }

    public PerfilSignatario comKeyUsage(int bits) {
        return new PerfilSignatario(politica, bits, dn, sanOid, sanValor, algoritmo, bitsChave, extensaoCriticaDesconhecida, validade);
    }

    public PerfilSignatario comDn(String novoDn) {
        return new PerfilSignatario(politica, keyUsage, novoDn, sanOid, sanValor, algoritmo, bitsChave, extensaoCriticaDesconhecida, validade);
    }

    public PerfilSignatario comSan(String oid, String valor) {
        return new PerfilSignatario(politica, keyUsage, dn, oid, valor, algoritmo, bitsChave, extensaoCriticaDesconhecida, validade);
    }

    public PerfilSignatario comChave(String novoAlgoritmo, int bits) {
        return new PerfilSignatario(politica, keyUsage, dn, sanOid, sanValor, novoAlgoritmo, bits, extensaoCriticaDesconhecida, validade);
    }

    public PerfilSignatario comExtensaoCriticaDesconhecida() {
        return new PerfilSignatario(politica, keyUsage, dn, sanOid, sanValor, algoritmo, bitsChave, true, validade);
    }

    public PerfilSignatario comValidade(Period periodo) {
        return new PerfilSignatario(politica, keyUsage, dn, sanOid, sanValor, algoritmo, bitsChave,
                extensaoCriticaDesconhecida, periodo);
    }
}
