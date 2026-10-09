/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IVersionProvider;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;

import java.io.PrintWriter;

/**
 * Linha de comando do Safira: {@code safira assinar} e {@code safira validar} sobre os serviços do
 * {@code safira-rest}, no modo {@code icpbrasil} (padrão) ou {@code simulacao}.
 *
 * <p>Códigos de saída ({@link CodigosDeSaida}): 0 sucesso/válido; 3 uso/configuração; 4 inconclusivo;
 * 6 reprovação definitiva; 1 erro interno. O stdout recebe só o JSON de resultado.
 */
@Command(name = "safira", mixinStandardHelpOptions = true, versionProvider = SafiraCli.Versao.class,
        subcommands = {Assinar.class, Validar.class, Servidor.class, Simulador.class},
        description = "Assina e valida Bundles FHIR (JAdES, política 0.2.0) no modo ICP-Brasil ou simulação.",
        exitCodeListHeading = "%nCódigos de saída:%n",
        exitCodeList = {"0:sucesso (assinatura criada ou VALIDATION.SUCCESS)",
                "3:erro de uso ou configuração (argumentos, arquivos, JSON, limites)",
                "4:inconclusivo (INDETERMINATE, revogação/carimbo/acervo indisponível, rede)",
                "6:reprovação definitiva (assinatura inválida, revogado, não confiável)",
                "1:erro interno"})
public final class SafiraCli implements Runnable {

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        throw new ParameterException(spec.commandLine(), "informe um comando: assinar, validar, servidor ou simulador.");
    }

    /** Linha de comando configurada (códigos de saída e tratamento de erros da CLI). */
    public static CommandLine linhaDeComando() {
        TratadorDeErros tratador = new TratadorDeErros();
        return new CommandLine(new SafiraCli())
                .setParameterExceptionHandler(tratador)
                .setExecutionExceptionHandler(tratador);
    }

    public static void main(String[] args) {
        // PrintWriter direto sobre o PrintStream: checkError() enxerga a falha do stdout (ex.: pipe fechado)
        System.exit(linhaDeComando().setOut(new PrintWriter(System.out, true)).execute(args));
    }

    /** Versão do jar (manifesto); em desenvolvimento, sem versão. */
    static final class Versao implements IVersionProvider {

        @Override
        public String[] getVersion() {
            String versao = SafiraCli.class.getPackage().getImplementationVersion();
            return new String[] {"safira " + (versao != null ? versao : "(desenvolvimento)")};
        }
    }
}
