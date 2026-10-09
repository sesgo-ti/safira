/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.cli.GerenciadorDoServidor.FalhaDoServidor;
import br.gov.go.saude.fhir.safira.simulador.AvisoSimulacaoAdvice;
import picocli.CommandLine.Command;
import picocli.CommandLine.Mixin;
import picocli.CommandLine.Model.CommandSpec;
import picocli.CommandLine.Option;
import picocli.CommandLine.ParameterException;
import picocli.CommandLine.Spec;
import tools.jackson.databind.json.JsonMapper;

import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.function.Function;

/**
 * {@code safira servidor iniciar|parar|status}: servidor local (API REST do Safira) em segundo plano, um
 * por modo, sempre em loopback. O estado fica em {@code <estado-dir>/<modo>/} (padrão
 * {@code ~/.safira/servidor}). O stdout recebe só o JSON de status; avisos e erros vão para o stderr.
 */
@Command(name = "servidor", description = "Servidor local da API do Safira (loopback) em segundo plano.",
        subcommands = {Servidor.Iniciar.class, Servidor.Parar.class, Servidor.Status.class, Servidor.Executar.class})
final class Servidor implements Runnable {

    static final String VARIAVEL_ESTADO = "SAFIRA_SERVIDOR_DIR";
    static final String AVISO_LOCAL = "servidor local, não é implantação de produção.";

    @Spec
    CommandSpec spec;

    @Override
    public void run() {
        throw new ParameterException(spec.commandLine(), "informe um comando: iniciar, parar ou status.");
    }

    /** Base do estado: {@code --estado-dir}, {@code SAFIRA_SERVIDOR_DIR} ou {@code ~/.safira/servidor}. */
    static Path base(Path opcao, Function<String, String> ambiente) {
        if (opcao != null) {
            return opcao;
        }
        String variavel = ambiente.apply(VARIAVEL_ESTADO);
        return variavel != null && !variavel.isBlank() ? Path.of(variavel)
                : Path.of(System.getProperty("user.home"), ".safira", "servidor");
    }

    /** Executa um comando do servidor traduzindo falhas em códigos de saída e emitindo o JSON. */
    static int executar(CommandSpec spec, Callable<Object> comando) {
        PrintWriter err = spec.commandLine().getErr();
        try {
            Object json = comando.call();
            PrintWriter out = spec.commandLine().getOut();
            out.println(JsonMapper.builder().build().writeValueAsString(json));
            out.flush();
            return out.checkError() ? CodigosDeSaida.ERRO_INTERNO : CodigosDeSaida.SUCESSO;
        } catch (FalhaDeUso e) {
            err.println("Erro: " + e.getMessage());
            return CodigosDeSaida.USO;
        } catch (FalhaDoServidor e) {
            err.println("Erro: " + e.getMessage());
            return e.saida();
        } catch (Exception e) {
            err.println("Erro interno: " + e.getMessage());
            return CodigosDeSaida.ERRO_INTERNO;
        } finally {
            err.flush();
        }
    }

    /** Opção {@code --modo} (padrão icpbrasil, como em assinar e validar). */
    static final class OpcaoModo {

        @Option(names = "--modo", paramLabel = "icpbrasil|simulacao", defaultValue = "icpbrasil",
                converter = Modo.Conversor.class,
                description = "Modo do servidor: icpbrasil (padrão) ou simulacao (SEM validade jurídica ICP-Brasil).")
        Modo modo;
    }

    /** Opção {@code --estado-dir}. */
    static final class OpcaoEstado {

        @Option(names = "--estado-dir", paramLabel = "DIR",
                description = "Base do estado (PID, porta, log), um subdiretório por modo "
                        + "(padrão SAFIRA_SERVIDOR_DIR ou ~/.safira/servidor).")
        Path estadoDir;

        /** Leitura das variáveis de ambiente (substituível nos testes). */
        Function<String, String> ambiente = System::getenv;

        Path diretorio(Modo modo) {
            return EstadoDoServidor.diretorio(base(estadoDir, ambiente), modo);
        }
    }

    @Command(name = "iniciar", description = "Sobe o servidor em segundo plano e espera a prontidão.", sortOptions = false)
    static final class Iniciar implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        OpcaoModo opcaoModo;

        @Mixin
        OpcaoEstado opcaoEstado;

        @Option(names = "--porta", paramLabel = "PORTA",
                description = "Porta em 127.0.0.1 (padrão SAFIRA_PORT, ou 8080 icpbrasil e 8081 simulacao).")
        Integer porta;

        @Option(names = "--pki-dir", paramLabel = "DIR",
                description = "Diretório da PKI simulada (só com --modo simulacao; padrão ~/.safira-simulador/pki).")
        Path pkiDir;

        @Option(names = "--config", paramLabel = "ARQUIVO.yml",
                description = "Configuração adicional (ex.: allowlist safira.policy.* e tsa-url no modo icpbrasil).")
        Path config;

        @Option(names = "--timeout", paramLabel = "SEGUNDOS",
                description = "Espera máxima pela prontidão (padrão 60 simulacao, 300 icpbrasil: a 1ª partida baixa o acervo).")
        Integer timeout;

        @Override
        public Integer call() {
            Modo modo = opcaoModo.modo;
            PrintWriter err = spec.commandLine().getErr();
            err.println("AVISO: " + (modo.simulacao() ? AvisoSimulacaoAdvice.TEXTO + "; " : "") + AVISO_LOCAL);
            err.flush();
            return executar(spec, () -> {
                if (pkiDir != null && !modo.simulacao()) {
                    throw new FalhaDeUso("--pki-dir só vale com --modo simulacao: os modos não se misturam.");
                }
                if (config != null && (!Files.isRegularFile(config) || !Files.isReadable(config))) {
                    throw new FalhaDeUso("Arquivo de configuração não encontrado ou ilegível: " + config);
                }
                if (timeout != null && (timeout < 1 || timeout > 3600)) {
                    throw new FalhaDeUso("--timeout deve estar entre 1 e 3600 segundos.");
                }
                int portaEfetiva = GerenciadorDoServidor.porta(porta, opcaoEstado.ambiente, modo);
                Duration espera = Duration.ofSeconds(timeout != null ? timeout : modo.simulacao() ? 60 : 300);
                return new GerenciadorDoServidor(err).iniciar(new GerenciadorDoServidor.Partida(modo,
                        opcaoEstado.diretorio(modo), portaEfetiva, pkiDir, config, espera));
            });
        }
    }

    @Command(name = "parar", description = "Encerra o servidor (SIGTERM; forçado após o timeout) e limpa o estado.",
            sortOptions = false)
    static final class Parar implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        OpcaoModo opcaoModo;

        @Mixin
        OpcaoEstado opcaoEstado;

        @Option(names = "--timeout", paramLabel = "SEGUNDOS", defaultValue = "30",
                description = "Espera pelo desligamento gracioso antes de forçar (padrão ${DEFAULT-VALUE}).")
        int timeout;

        @Override
        public Integer call() {
            return executar(spec, () -> {
                if (timeout < 1 || timeout > 3600) {
                    throw new FalhaDeUso("--timeout deve estar entre 1 e 3600 segundos.");
                }
                Modo modo = opcaoModo.modo;
                return new GerenciadorDoServidor(spec.commandLine().getErr())
                        .parar(modo, opcaoEstado.diretorio(modo), Duration.ofSeconds(timeout));
            });
        }
    }

    @Command(name = "status", description = "Estado do servidor (UP, DOWN ou PARADO) em JSON; sem --modo, dos dois modos.")
    static final class Status implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Option(names = "--modo", paramLabel = "icpbrasil|simulacao", converter = Modo.Conversor.class,
                description = "Modo consultado (padrão: os dois).")
        Modo modo;

        @Mixin
        OpcaoEstado opcaoEstado;

        @Override
        public Integer call() {
            return executar(spec, () -> {
                GerenciadorDoServidor gerenciador = new GerenciadorDoServidor(spec.commandLine().getErr());
                if (modo != null) {
                    return gerenciador.status(modo, opcaoEstado.diretorio(modo));
                }
                Map<String, Object> agregado = new LinkedHashMap<>();
                agregado.put("servidores", List.of(Modo.values()).stream()
                        .map(cada -> gerenciador.status(cada, opcaoEstado.diretorio(cada))).toList());
                return agregado;
            });
        }
    }

    /** Processo filho de {@code iniciar} (uso interno): roda a aplicação do modo neste processo. */
    @Command(name = "executar", hidden = true)
    static final class Executar implements Callable<Integer> {

        @Spec
        CommandSpec spec;

        @Mixin
        OpcaoModo opcaoModo;

        @Option(names = "--porta", required = true)
        int porta;

        @Option(names = "--pki-dir")
        Path pkiDir;

        @Option(names = "--config")
        Path config;

        @Override
        public Integer call() throws InterruptedException {
            try {
                ExecucaoDoServidor.executar(opcaoModo.modo, porta, pkiDir, config);
                return CodigosDeSaida.SUCESSO;
            } catch (RuntimeException e) {
                spec.commandLine().getErr().println("Erro: falha na partida do servidor (modo "
                        + opcaoModo.modo.nome() + "): " + e.getMessage());
                spec.commandLine().getErr().flush();
                return CodigosDeSaida.USO;
            }
        }
    }
}
