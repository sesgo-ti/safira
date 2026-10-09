/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine.Option;

import java.nio.file.Path;

/** Opções comuns de {@code assinar} e {@code validar}. */
final class OpcoesComuns {

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

    @Option(names = "--verbose", description = "Mostra a causa de falhas (stack trace) no stderr.")
    boolean verbose;
}
