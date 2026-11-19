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
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Tratamento de erros do picocli: erro de uso sai com 3 e exceção inesperada com 1, sempre no stderr.
 * Argumentos desconhecidos são citados só pelo nome da opção, nunca pelo valor nem pelo argumento
 * seguinte (um {@code --senha x} ou {@code --senha -x} digitado por engano não é ecoado).
 */
final class TratadorDeErros implements IParameterExceptionHandler, IExecutionExceptionHandler {

    @Override
    public int handleParseException(ParameterException ex, String[] args) {
        CommandLine linha = ex.getCommandLine();
        PrintWriter err = linha.getErr();
        if (ex instanceof UnmatchedArgumentException naoReconhecido) {
            List<String> opcoes = nomesDasOpcoes(naoReconhecido.getUnmatched());
            err.println("Erro: argumento não reconhecido" + (opcoes.isEmpty() ? "" : ": " + String.join(", ", opcoes))
                    + " (valores omitidos).");
            if (opcoes.contains("--senha")) {
                err.println("A senha nunca é aceita como argumento: use --senha-arquivo, --senha-env ou --senha-stdin.");
            }
        } else {
            err.println("Erro: " + traduzir(ex.getMessage()));
        }
        err.println("Use '" + linha.getCommandSpec().qualifiedName() + " --help' para ver as opções.");
        err.flush();
        return CodigosDeSaida.USO;
    }

    /** Mensagens do picocli (em inglês, às vezes com prefixo {@code Error: }) traduzidas; as demais ficam como estão. */
    private static final List<Map.Entry<Pattern, String>> TRADUCOES = List.of(
            Map.entry(Pattern.compile("Missing required argument \\(specify one of these\\): (.*)", Pattern.DOTALL),
                    "informe uma destas opções: $1"),
            Map.entry(Pattern.compile("Missing required argument\\(s\\): (.*)", Pattern.DOTALL),
                    "argumento obrigatório ausente: $1"),
            Map.entry(Pattern.compile("Missing required options?: (.*)", Pattern.DOTALL), "opção obrigatória ausente: $1"),
            Map.entry(Pattern.compile("Missing required parameter for option '([^']*)'.*", Pattern.DOTALL),
                    "falta o valor da opção $1"),
            Map.entry(Pattern.compile("Expected parameter for option '([^']*)'.*", Pattern.DOTALL),
                    "falta o valor da opção $1"),
            Map.entry(Pattern.compile("Invalid value for option '([^']*)': (.*)", Pattern.DOTALL),
                    "valor inválido para a opção $1: $2"),
            Map.entry(Pattern.compile("(.*) are mutually exclusive \\(specify only one\\)", Pattern.DOTALL),
                    "as opções $1 são mutuamente exclusivas (informe só uma)"),
            Map.entry(Pattern.compile("option '([^']*)' \\([^)]*\\) should be specified only once.*", Pattern.DOTALL),
                    "a opção $1 deve ser informada uma única vez"));

    /** Mensagem do picocli em português, sem o prefixo {@code Error: } (a CLI já escreve {@code Erro: }). */
    static String traduzir(String mensagem) {
        String texto = mensagem == null ? "" : mensagem.strip();
        if (texto.startsWith("Error: ")) {
            texto = texto.substring("Error: ".length());
        }
        for (Map.Entry<Pattern, String> traducao : TRADUCOES) {
            Matcher casamento = traducao.getKey().matcher(texto);
            if (casamento.matches()) {
                return casamento.replaceFirst(traducao.getValue());
            }
        }
        return texto;
    }

    /**
     * Só o nome de cada opção desconhecida: o valor após {@code =} e o argumento seguinte a uma opção
     * desconhecida (possível valor, como em {@code --senha -Segredo}) nunca são citados.
     */
    static List<String> nomesDasOpcoes(List<String> naoReconhecidos) {
        List<String> nomes = new ArrayList<>();
        boolean posOpcao = false;
        for (String argumento : naoReconhecidos) {
            if (!posOpcao && argumento.startsWith("-")) {
                nomes.add(argumento.contains("=") ? argumento.substring(0, argumento.indexOf('=')) : argumento);
                posOpcao = !argumento.contains("=");
            } else {
                posOpcao = false;
            }
        }
        return nomes;
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
