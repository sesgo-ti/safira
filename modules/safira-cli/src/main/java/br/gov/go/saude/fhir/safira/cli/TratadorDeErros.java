/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine;
import picocli.CommandLine.IExecutionExceptionHandler;
import picocli.CommandLine.IParameterExceptionHandler;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.ParseResult;
import picocli.CommandLine.UnmatchedArgumentException;

import java.io.PrintWriter;
import java.util.List;

/**
 * Tratamento de erros do picocli: erro de uso sai com 3 e exceção inesperada com 1, sempre no stderr.
 * Argumentos desconhecidos são citados só pelo nome da opção, nunca pelo valor (um {@code --senha x}
 * digitado por engano não é ecoado).
 */
final class TratadorDeErros implements IParameterExceptionHandler, IExecutionExceptionHandler {

    @Override
    public int handleParseException(ParameterException ex, String[] args) {
        CommandLine linha = ex.getCommandLine();
        PrintWriter err = linha.getErr();
        if (ex instanceof UnmatchedArgumentException naoReconhecido) {
            List<String> opcoes = naoReconhecido.getUnmatched().stream()
                    .filter(argumento -> argumento.startsWith("-"))
                    .map(argumento -> argumento.contains("=") ? argumento.substring(0, argumento.indexOf('=')) : argumento)
                    .toList();
            err.println("Erro: argumento não reconhecido" + (opcoes.isEmpty() ? "" : ": " + String.join(", ", opcoes))
                    + " (valores omitidos).");
            if (opcoes.contains("--senha")) {
                err.println("A senha nunca é aceita como argumento: use --senha-arquivo, --senha-env ou --senha-stdin.");
            }
        } else {
            err.println("Erro: " + ex.getMessage());
        }
        err.println("Use '" + linha.getCommandSpec().qualifiedName() + " --help' para ver as opções.");
        err.flush();
        return CodigosDeSaida.USO;
    }

    @Override
    public int handleExecutionException(Exception ex, CommandLine linha, ParseResult resultado) {
        PrintWriter err = linha.getErr();
        err.println("Erro interno: " + ex.getClass().getSimpleName() + ". Use --verbose para ver a causa.");
        if (verbose(resultado)) {
            ex.printStackTrace(err);
        }
        err.flush();
        return CodigosDeSaida.ERRO_INTERNO;
    }

    private static boolean verbose(ParseResult resultado) {
        for (ParseResult atual = resultado; atual != null; atual = atual.subcommand()) {
            if (atual.hasMatchedOption("--verbose")) {
                return true;
            }
        }
        return false;
    }
}
