/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.simulador;

import br.gov.go.saude.fhir.safira.testkit.PkiIcpSimulada;

import java.nio.file.Path;

/**
 * PKI simulada (SEM VALOR LEGAL) persistida em diretório pelo {@link RepositorioPkiSimulada}: caminhos
 * dos arquivos, valores da allowlist e a PKI em memória (fontes OCSP, LCR e TSA). A senha dos
 * PKCS#12 só existe no arquivo {@link #senha()}.
 *
 * @param diretorio    diretório da PKI (absoluto)
 * @param raiz         PEM da raiz (âncora)
 * @param ac           PEM da AC intermediária
 * @param signatario   PKCS#12 do signatário válido (alias {@link GeradorPkiSimulada#ALIAS_SIGNATARIO})
 * @param revogado     PKCS#12 do signatário revogado (alias {@link GeradorPkiSimulada#ALIAS_REVOGADO})
 * @param senha        arquivo com a senha dos PKCS#12
 * @param politicaOid  OID de política A3 do signatário
 * @param issuerSha256 SHA-256 (hex minúsculo) do DER da AC emissora
 * @param pki          PKI em memória
 * @param situacao     o que a abertura fez com o diretório
 */
public record PkiPersistida(Path diretorio, Path raiz, Path ac, Path signatario, Path revogado, Path senha,
                            String politicaOid, String issuerSha256, PkiIcpSimulada pki, Situacao situacao) {

    /** Resultado da abertura do diretório. */
    public enum Situacao {
        /** Diretório vazio ou inexistente: PKI nova gerada e gravada. */
        GERADA,
        /** PKI existente carregada como estava. */
        REUTILIZADA,
        /** PKI existente carregada com o certificado do signatário renovado (vencido ou perto de vencer). */
        FOLHA_RENOVADA
    }
}
