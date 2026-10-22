/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UncheckedIOException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Function;
import java.util.jar.JarFile;

/**
 * Ciclo de vida do servidor local de um modo: sobe a própria CLI em segundo plano
 * ({@code servidor executar}), grava o estado ({@link EstadoDoServidor}), espera a prontidão
 * ({@code /actuator/health/readiness}) e encerra de forma graciosa. Um servidor por modo e diretório.
 */
final class GerenciadorDoServidor {

    static final String VARIAVEL_PORTA = "SAFIRA_PORT";
    static final String PRONTIDAO = "/actuator/health/readiness";

    private static final Duration INTERVALO = Duration.ofMillis(250);
    private static final Duration TIMEOUT_DA_SONDA = Duration.ofSeconds(2);
    private static final Duration TIMEOUT_FORCADO = Duration.ofSeconds(10);
    private static final Duration ESPERA_DO_INICIO = Duration.ofSeconds(2);
    private static final String PREFIXO_DO_ERRO = "Erro: ";

    /** Falha com o código de saída da CLI. */
    static final class FalhaDoServidor extends RuntimeException {

        private final int saida;

        FalhaDoServidor(String mensagem, int saida) {
            super(mensagem);
            this.saida = saida;
        }

        int saida() {
            return saida;
        }
    }

    /** O que subir: modo, diretório do estado, porta, opções do modo e limites de tempo. */
    record Partida(Modo modo, Path diretorio, int porta, Path pkiDir, Path config, Duration timeout,
                   Duration ociosidade) {
    }

    private final PrintWriter err;

    GerenciadorDoServidor(PrintWriter err) {
        this.err = err;
    }

    /** Porta: {@code --porta}, senão {@code SAFIRA_PORT}, senão 8080 (icpbrasil) ou 8081 (simulação). */
    static int porta(Integer opcao, Function<String, String> ambiente, Modo modo) {
        if (opcao != null) {
            return valida(opcao, "--porta");
        }
        String variavel = ambiente.apply(VARIAVEL_PORTA);
        if (variavel == null || variavel.isBlank()) {
            return modo.simulacao() ? 8081 : 8080;
        }
        try {
            return valida(Integer.parseInt(variavel.strip()), VARIAVEL_PORTA);
        } catch (NumberFormatException e) {
            throw new FalhaDeUso(VARIAVEL_PORTA + " não é uma porta válida: '" + variavel + "'.");
        }
    }

    private static int valida(int porta, String origem) {
        if (porta < 1 || porta > 65_535) {
            throw new FalhaDeUso(origem + " deve estar entre 1 e 65535 (recebido " + porta + ").");
        }
        return porta;
    }

    /** Sobe o servidor e espera a prontidão; devolve o status (UP). */
    Map<String, Object> iniciar(Partida partida) {
        Path dir = partida.diretorio();
        try (EstadoDoServidor.Trava trava = travar(dir)) {
            Optional<EstadoDoServidor> anterior = lerOuDescartar(dir);
            if (anterior.isPresent()) {
                EstadoDoServidor estado = anterior.get();
                if (estado.processo().isPresent()) {
                    throw new FalhaDeUso("O servidor " + partida.modo().nome() + " já está em execução (PID "
                            + estado.pid() + ", porta " + estado.porta() + "). Use 'safira servidor parar --modo "
                            + partida.modo().nome() + "'.");
                }
                limparOrfao(dir, estado);
            }
            exigirPortaLivre(partida.porta());
            Path log = dir.resolve(EstadoDoServidor.LOG);
            Process processo = lancar(partida, log);
            EstadoDoServidor estado = new EstadoDoServidor(partida.modo(), processo.pid(), partida.porta(),
                    inicioDe(processo), java(), Instant.now(), log);
            try {
                estado.gravar(dir);
                esperarProntidao(processo, estado, dir, partida.timeout());
            } catch (FalhaDoServidor e) {
                throw e;
            } catch (RuntimeException e) {
                // nenhum filho fica órfão: qualquer falha depois do fork o encerra
                encerrar(processo.toHandle(), TIMEOUT_FORCADO);
                EstadoDoServidor.remover(dir);
                throw new FalhaDoServidor("Falha ao registrar o servidor (PID " + processo.pid() + "): "
                        + e.getMessage() + "; processo encerrado.", CodigosDeSaida.ERRO_INTERNO);
            }
            return status(partida.modo(), estado, true);
        }
    }

    /** Encerra o servidor (SIGTERM, depois forçado após o timeout) e limpa o estado; sem servidor, nada a fazer. */
    Map<String, Object> parar(Modo modo, Path dir, Duration timeout) {
        try (EstadoDoServidor.Trava trava = travar(dir)) {
            Optional<EstadoDoServidor> lido = lerOuDescartar(dir);
            if (lido.isEmpty()) {
                return parado(modo);
            }
            EstadoDoServidor estado = lido.get();
            Optional<ProcessHandle> processo = estado.processo();
            if (processo.isEmpty()) {
                limparOrfao(dir, estado);
                return parado(modo);
            }
            encerrar(processo.get(), timeout);
            EstadoDoServidor.remover(dir);
            Map<String, Object> status = parado(modo);
            status.put("pid", estado.pid());
            return status;
        }
    }

    /** Status do modo; estado órfão é limpo (se nenhuma outra operação estiver em andamento). */
    Map<String, Object> status(Modo modo, Path dir) {
        Optional<EstadoDoServidor> lido;
        try {
            lido = EstadoDoServidor.ler(dir);
        } catch (EstadoDoServidor.Ilegivel e) {
            EstadoDoServidor.travar(dir).ifPresent(trava -> {
                try (EstadoDoServidor.Trava posse = trava) {
                    lerOuDescartar(dir);
                }
            });
            return parado(modo);
        }
        if (lido.isEmpty()) {
            return parado(modo);
        }
        EstadoDoServidor estado = lido.get();
        if (estado.processo().isPresent()) {
            return status(modo, estado, pronto(estado.porta()));
        }
        Optional<EstadoDoServidor.Trava> trava = EstadoDoServidor.travar(dir);
        if (trava.isPresent()) {
            try (EstadoDoServidor.Trava posse = trava.get()) {
                // relido sob a trava: um iniciar pode ter acabado de gravar um estado novo
                lerOuDescartar(dir).filter(atual -> atual.processo().isEmpty())
                        .ifPresent(orfao -> limparOrfao(dir, orfao));
            }
        }
        return parado(modo);
    }

    /**
     * Estado de {@code dir}; ilegível é tratado como órfão (sem PID confiável não há o que encerrar):
     * o arquivo é removido com aviso e nenhum processo é tocado. Só sob a trava de operação.
     */
    private Optional<EstadoDoServidor> lerOuDescartar(Path dir) {
        try {
            return EstadoDoServidor.ler(dir);
        } catch (EstadoDoServidor.Ilegivel e) {
            EstadoDoServidor.remover(dir);
            err.println("AVISO: " + e.getMessage() + "; tratado como órfão e removido (nenhum processo foi "
                    + "encerrado; se um servidor ainda ocupar a porta, encerre-o manualmente).");
            err.flush();
            return Optional.empty();
        }
    }

    private static EstadoDoServidor.Trava travar(Path dir) {
        return EstadoDoServidor.travar(dir).orElseThrow(() -> new FalhaDeUso(
                "Outra operação de 'safira servidor' está em andamento em " + dir + "."));
    }

    /**
     * Remove o estado sem encerrar processo algum. Se o PID estiver vivo sem identidade confirmada (PID
     * reaproveitado, início ou comando desconhecidos), o processo é de outro dono e não é tocado.
     */
    private void limparOrfao(Path dir, EstadoDoServidor estado) {
        EstadoDoServidor.remover(dir);
        err.println(estado.vivo().isPresent()
                ? "AVISO: estado órfão removido: o PID " + estado.pid() + " está vivo, mas não foi confirmado como o "
                        + "servidor (início ou comando não conferem) e não foi encerrado."
                : "AVISO: estado órfão removido (PID " + estado.pid() + " não está em execução).");
        err.flush();
    }

    /**
     * Instante de início do filho segundo o SO, esperado por até {@link #ESPERA_DO_INICIO}; sem ele o
     * servidor não poderia ser identificado depois, então o filho é encerrado.
     */
    private static Instant inicioDe(Process processo) {
        Instant limite = Instant.now().plus(ESPERA_DO_INICIO);
        while (true) {
            Optional<Instant> inicio = processo.info().startInstant();
            if (inicio.isPresent()) {
                return inicio.get();
            }
            if (Instant.now().isAfter(limite)) {
                encerrar(processo.toHandle(), TIMEOUT_FORCADO);
                throw new FalhaDoServidor("Não foi possível obter o instante de início do processo " + processo.pid()
                        + " para identificá-lo; processo encerrado.", CodigosDeSaida.ERRO_INTERNO);
            }
            try {
                Thread.sleep(INTERVALO);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                encerrar(processo.toHandle(), TIMEOUT_FORCADO);
                throw new FalhaDoServidor("Espera interrompida; servidor encerrado.", CodigosDeSaida.ERRO_INTERNO);
            }
        }
    }

    private static void exigirPortaLivre(int porta) {
        try (ServerSocket teste = new ServerSocket()) {
            teste.setReuseAddress(false);
            teste.bind(new InetSocketAddress(InetAddress.getByName(ExecucaoDoServidor.LOOPBACK), porta));
        } catch (IOException e) {
            throw new FalhaDeUso("A porta " + porta + " já está em uso em " + ExecucaoDoServidor.LOOPBACK
                    + "; escolha outra com --porta ou " + VARIAVEL_PORTA + ".");
        }
    }

    private static Process lancar(Partida partida, Path log) {
        try {
            EstadoDoServidor.criarPrivado(log);
            Process processo = new ProcessBuilder(comando(partida))
                    .redirectErrorStream(true)
                    .redirectOutput(ProcessBuilder.Redirect.appendTo(log.toFile()))
                    .start();
            processo.getOutputStream().close();
            return processo;
        } catch (IOException e) {
            throw new UncheckedIOException("Não foi possível iniciar o processo do servidor", e);
        }
    }

    /**
     * Comando do filho: a mesma {@code java} e o mesmo classpath deste processo, rodando
     * {@code safira servidor executar}. Do jar executável do Spring Boot, {@code -jar}; senão (IDE,
     * testes), {@code -cp} com a classe principal da CLI. Com {@code nohup} quando existir, o servidor
     * sobrevive ao fechamento do terminal ({@code nohup} faz {@code exec}: o PID é o da JVM).
     */
    static List<String> comando(Partida partida) {
        List<String> comando = new ArrayList<>();
        Path nohup = Path.of("/usr/bin/nohup");
        if (Files.isExecutable(nohup)) {
            comando.add(nohup.toString());
        }
        comando.add(java());
        comando.add("-Duser.home=" + System.getProperty("user.home"));
        String classpath = System.getProperty("java.class.path");
        if (jarExecutavel(classpath)) {
            comando.add("-jar");
            comando.add(Path.of(classpath).toAbsolutePath().toString());
        } else {
            comando.add("-cp");
            comando.add(classpath);
            comando.add(SafiraCli.class.getName());
        }
        comando.addAll(List.of("servidor", "executar", "--modo", partida.modo().nome(),
                "--porta", String.valueOf(partida.porta())));
        if (partida.pkiDir() != null) {
            comando.addAll(List.of("--pki-dir", partida.pkiDir().toAbsolutePath().toString()));
        }
        if (partida.config() != null) {
            comando.addAll(List.of("--config", partida.config().toAbsolutePath().toString()));
        }
        if (partida.ociosidade() != null) {
            comando.addAll(List.of("--ociosidade", partida.ociosidade().toString()));
        }
        return comando;
    }

    /**
     * O executável {@code java} deste processo, como o SO o informa: o filho roda o mesmo, e é com ele que
     * a identidade do filho é conferida depois.
     */
    static String java() {
        return ProcessHandle.current().info().command()
                .orElse(Path.of(System.getProperty("java.home"), "bin", "java").toString());
    }

    /** Um único jar com {@code Start-Class} no manifesto: o jar executável do Spring Boot. */
    private static boolean jarExecutavel(String classpath) {
        if (classpath == null || classpath.contains(File.pathSeparator) || !classpath.endsWith(".jar")) {
            return false;
        }
        try (JarFile jar = new JarFile(classpath)) {
            return jar.getManifest() != null && jar.getManifest().getMainAttributes().getValue("Start-Class") != null;
        } catch (IOException e) {
            return false;
        }
    }

    private void esperarProntidao(Process processo, EstadoDoServidor estado, Path dir, Duration timeout) {
        Instant limite = Instant.now().plus(timeout);
        while (true) {
            if (!processo.isAlive()) {
                EstadoDoServidor.remover(dir);
                throw new FalhaDoServidor("O servidor terminou durante a partida (saída " + processo.exitValue()
                        + ")." + causaNoLog(estado.log()) + " Log completo: " + estado.log(), CodigosDeSaida.USO);
            }
            if (pronto(estado.porta())) {
                return;
            }
            if (Instant.now().isAfter(limite)) {
                encerrar(processo.toHandle(), TIMEOUT_FORCADO);
                EstadoDoServidor.remover(dir);
                throw new FalhaDoServidor("O servidor (PID " + processo.pid() + ") não ficou pronto em "
                        + timeout.toSeconds() + " s; processo encerrado. Log: " + estado.log(), CodigosDeSaida.INCONCLUSIVO);
            }
            try {
                Thread.sleep(INTERVALO);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                encerrar(processo.toHandle(), TIMEOUT_FORCADO);
                EstadoDoServidor.remover(dir);
                throw new FalhaDoServidor("Espera interrompida; servidor encerrado.", CodigosDeSaida.ERRO_INTERNO);
            }
        }
    }

    /** SIGTERM (desligamento gracioso do Spring); após o timeout, forçado. */
    static void encerrar(ProcessHandle processo, Duration timeout) {
        processo.destroy();
        try {
            processo.onExit().get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException | ExecutionException e) {
            processo.destroyForcibly();
            try {
                processo.onExit().get(TIMEOUT_FORCADO.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException | ExecutionException ignorada) {
                throw new FalhaDoServidor("O processo " + processo.pid() + " não terminou.", CodigosDeSaida.ERRO_INTERNO);
            } catch (InterruptedException interrompida) {
                Thread.currentThread().interrupt();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** {@code GET /actuator/health/readiness} em loopback responde 200. */
    static boolean pronto(int porta) {
        try (HttpClient cliente = HttpClient.newBuilder().connectTimeout(TIMEOUT_DA_SONDA)
                .followRedirects(HttpClient.Redirect.NEVER).build()) {
            HttpRequest requisicao = HttpRequest.newBuilder(URI.create(url(porta) + PRONTIDAO))
                    .timeout(TIMEOUT_DA_SONDA).GET().build();
            return cliente.send(requisicao, HttpResponse.BodyHandlers.discarding()).statusCode() == 200;
        } catch (IOException e) {
            return false;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return false;
        }
    }

    static String url(int porta) {
        return "http://" + ExecucaoDoServidor.LOOPBACK + ":" + porta;
    }

    /**
     * Última mensagem curta do filho ({@code Erro: ...}, escrita pela CLI) no log; o log do Spring, com
     * stack traces, fica só no arquivo.
     */
    private static String causaNoLog(Path log) {
        try {
            List<String> linhas = Files.readAllLines(log);
            for (int i = linhas.size() - 1; i >= 0; i--) {
                if (linhas.get(i).startsWith(PREFIXO_DO_ERRO)) {
                    return " Causa: " + linhas.get(i).substring(PREFIXO_DO_ERRO.length()).strip().replaceAll("\\.$", "") + ".";
                }
            }
            return "";
        } catch (IOException | UncheckedIOException e) {
            return "";
        }
    }

    static Map<String, Object> parado(Modo modo) {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("modo", modo.nome());
        status.put("estado", "PARADO");
        return status;
    }

    private static Map<String, Object> status(Modo modo, EstadoDoServidor estado, boolean pronto) {
        Map<String, Object> status = new LinkedHashMap<>();
        status.put("modo", modo.nome());
        status.put("estado", pronto ? "UP" : "DOWN");
        status.put("pid", estado.pid());
        status.put("porta", estado.porta());
        status.put("url", url(estado.porta()));
        if (estado.iniciadoEm() != null) {
            status.put("inicio", estado.iniciadoEm().toString());
        }
        if (estado.log() != null) {
            status.put("log", estado.log().toString());
        }
        return status;
    }
}
