/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import picocli.CommandLine.Model.CommandSpec;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;

/**
 * Execução comum de {@code assinar} e {@code validar}: partida do contexto no modo, aviso de simulação,
 * emissão do JSON (stdout ou {@code --saida}) e tradução de falhas em códigos de saída. O stdout só
 * recebe o JSON de resultado; mensagens e, com {@code --verbose}, stack traces vão para o stderr.
 */
final class Execucao {

    /** Operação sobre o contexto iniciado. */
    @FunctionalInterface
    interface Operacao {
        Resultado executar(ContextoSafira contexto) throws Exception;
    }

    /** JSON de resultado e código de saída. */
    record Resultado(String json, int saida) {
    }

    private Execucao() {
    }

    static int executar(CommandSpec spec, OpcoesComuns opcoes, Operacao operacao) {
        PrintWriter out = spec.commandLine().getOut();
        PrintWriter err = spec.commandLine().getErr();
        ContextoSafira contexto;
        try {
            contexto = ContextoSafira.iniciar(opcoes.modo, opcoes.pkiDir, opcoes.config, opcoes.verbose);
        } catch (FalhaDeUso e) {
            err.println("Erro: " + e.getMessage());
            return CodigosDeSaida.USO;
        } catch (RuntimeException e) {
            err.println("Erro: falha na partida do Safira (modo " + opcoes.modo.nome() + "): " + causaRaiz(e));
            detalhar(opcoes, err, e);
            return CodigosDeSaida.USO;
        }
        try (contexto) {
            if (opcoes.modo.simulacao()) {
                err.println("AVISO: " + AvisoSimulacaoAdvice.TEXTO + contexto.pkiSimulada()
                        .map(pki -> " (PKI simulada em " + pki.diretorio() + ")").orElse(""));
            }
            Resultado resultado;
            try {
                resultado = operacao.executar(contexto);
            } catch (FalhaDeUso e) {
                err.println("Erro: " + e.getMessage());
                if (e.outcome() != null) {
                    emitir(opcoes, out, contexto.json(e.outcome()));
                }
                return CodigosDeSaida.USO;
            }
            emitir(opcoes, out, resultado.json());
            return resultado.saida();
        } catch (FalhaDeUso e) {
            err.println("Erro: " + e.getMessage());
            return CodigosDeSaida.USO;
        } catch (Exception e) {
            err.println("Erro interno: " + e.getClass().getSimpleName() + ". Use --verbose para ver a causa.");
            detalhar(opcoes, err, e);
            return CodigosDeSaida.ERRO_INTERNO;
        }
    }

    private static void emitir(OpcoesComuns opcoes, PrintWriter out, String json) {
        if (opcoes.saida == null) {
            out.println(json);
            out.flush();
            return;
        }
        try {
            Files.writeString(opcoes.saida, json + System.lineSeparator(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new FalhaDeUso("Não foi possível gravar " + opcoes.saida + ": " + e.getMessage());
        }
    }

    private static void detalhar(OpcoesComuns opcoes, PrintWriter err, Exception e) {
        if (opcoes.verbose) {
            e.printStackTrace(err);
            err.flush();
        }
    }

    private static String causaRaiz(Throwable e) {
        Throwable causa = e;
        while (causa.getCause() != null && causa.getCause() != causa) {
            causa = causa.getCause();
        }
        return causa.getMessage() != null ? causa.getMessage() : causa.getClass().getSimpleName();
    }
}
