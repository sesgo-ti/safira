/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine.Option;

import java.nio.file.Files;
import java.nio.file.Path;

/** Opções comuns de {@code assinar} e {@code validar}. */
final class OpcoesComuns {

    /** Intervalo aceito pela icpbrasil-truststore ({@code network.download-timeout-seconds}). */
    static final int TIMEOUT_ACERVO_MINIMO = 30;
    static final int TIMEOUT_ACERVO_MAXIMO = 300;


    @Option(names = "--modo", paramLabel = "icpbrasil|simulacao", defaultValue = "icpbrasil",
            converter = Modo.Conversor.class,
            description = "Fonte de confiança: icpbrasil (acervo ICP-Brasil, padrão) ou simulacao "
                    + "(PKI simulada, SEM validade jurídica ICP-Brasil).")
    Modo modo;

    @Option(names = "--pki-dir", paramLabel = "DIR",
            description = "Diretório da PKI simulada (só com --modo simulacao; padrão ~/.safira-simulador/pki, "
                    + "gerada na primeira execução).")
    Path pkiDir;

    @Option(names = "--config", paramLabel = "ARQUIVO.yml",
            description = "Configuração adicional do Safira (ex.: allowlist safira.policy.*, limites).")
    Path config;

    @Option(names = "--saida", paramLabel = "ARQUIVO",
            description = "Grava o JSON de resultado no arquivo em vez do stdout.")
    Path saida;

    @Option(names = "--timeout-acervo", paramLabel = "SEGUNDOS",
            description = "Timeout do download do acervo ICP-Brasil (só com --modo icpbrasil; 30 a 300; padrão 30, "
                    + "uma tentativa).")
    Integer timeoutAcervo;

    @Option(names = "--verbose", description = "Mostra a causa de falhas (stack trace) no stderr.")
    boolean verbose;

    /**
     * Conferências que dispensam o Spring: combinação de opções por modo, faixa do timeout e
     * existência/legibilidade dos arquivos de entrada. No modo simulação, os arquivos dentro do diretório
     * da PKI ({@code signatario.p12}, {@code senha.txt}) são conferidos depois da partida, que gera a PKI
     * na primeira execução.
     */
    void conferir(Path... entradas) {
        if (pkiDir != null && modo != Modo.SIMULACAO) {
            throw new FalhaDeUso("--pki-dir só vale com --modo simulacao: os modos não se misturam.");
        }
        if (timeoutAcervo != null) {
            if (modo != Modo.ICPBRASIL) {
                throw new FalhaDeUso("--timeout-acervo só vale com --modo icpbrasil: os modos não se misturam.");
            }
            if (timeoutAcervo < TIMEOUT_ACERVO_MINIMO || timeoutAcervo > TIMEOUT_ACERVO_MAXIMO) {
                throw new FalhaDeUso("--timeout-acervo deve estar entre " + TIMEOUT_ACERVO_MINIMO + " e "
                        + TIMEOUT_ACERVO_MAXIMO + " segundos.");
            }
        }
        if (config != null) {
            legivel(config, "Arquivo de configuração");
        }
        Path pki = modo == Modo.SIMULACAO ? diretorioDaPki() : null;
        for (Path entrada : entradas) {
            if (entrada != null && (pki == null || !entrada.toAbsolutePath().normalize().startsWith(pki))) {
                legivel(entrada, "Arquivo");
            }
        }
    }

    /** Diretório efetivo da PKI simulada: {@code --pki-dir}, {@code SAFIRA_SIMULADOR_DIRETORIO} ou o padrão. */
    private Path diretorioDaPki() {
        if (pkiDir != null) {
            return pkiDir.toAbsolutePath().normalize();
        }
        String ambiente = System.getenv("SAFIRA_SIMULADOR_DIRETORIO");
        Path diretorio = ambiente != null && !ambiente.isBlank() ? Path.of(ambiente)
                : Path.of(System.getProperty("user.home"), ".safira-simulador", "pki");
        return diretorio.toAbsolutePath().normalize();
    }

    private static void legivel(Path arquivo, String descricao) {
        if (!Files.isRegularFile(arquivo) || !Files.isReadable(arquivo)) {
            throw new FalhaDeUso(descricao + " não encontrado ou ilegível: " + arquivo);
        }
    }
}
