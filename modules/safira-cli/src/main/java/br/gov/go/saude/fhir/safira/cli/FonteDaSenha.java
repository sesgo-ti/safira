/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine.Option;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Origem da senha do PKCS#12: arquivo, variável de ambiente ou stdin (exatamente uma). A senha nunca é
 * aceita como argumento de linha de comando, onde ficaria visível na lista de processos e no histórico.
 */
final class FonteDaSenha {

    @Option(names = "--senha-arquivo", paramLabel = "ARQUIVO", required = true,
            description = "Arquivo com a senha (uma quebra de linha final é ignorada).")
    Path arquivo;

    @Option(names = "--senha-env", paramLabel = "VARIAVEL", required = true,
            description = "Nome da variável de ambiente com a senha.")
    String variavel;

    @Option(names = "--senha-stdin", required = true, description = "Lê a senha da primeira linha do stdin.")
    boolean stdin;

    String ler() {
        if (arquivo != null) {
            if (!Files.isRegularFile(arquivo)) {
                throw new FalhaDeUso("Arquivo de senha não encontrado: " + arquivo);
            }
            try {
                return semQuebraFinal(Files.readString(arquivo, StandardCharsets.UTF_8));
            } catch (IOException e) {
                throw new FalhaDeUso("Não foi possível ler o arquivo de senha " + arquivo + ".");
            }
        }
        if (variavel != null) {
            String valor = System.getenv(variavel);
            if (valor == null) {
                throw new FalhaDeUso("A variável de ambiente " + variavel + " não está definida.");
            }
            return valor;
        }
        try {
            String linha = new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8)).readLine();
            if (linha == null) {
                throw new FalhaDeUso("Nenhuma senha recebida no stdin.");
            }
            return linha;
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível ler a senha do stdin.");
        }
    }

    private static String semQuebraFinal(String texto) {
        if (texto.endsWith("\r\n")) {
            return texto.substring(0, texto.length() - 2);
        }
        return texto.endsWith("\n") ? texto.substring(0, texto.length() - 1) : texto;
    }
}
