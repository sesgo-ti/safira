/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import br.gov.go.saude.fhir.safira.app.SafiraApplication;
import br.gov.go.saude.fhir.safira.simulador.SimuladorApplication;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.event.ContextClosedEvent;

import java.nio.file.Path;
import java.time.Duration;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CountDownLatch;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Lado do processo filho de {@code safira servidor}: roda {@link SafiraApplication} (icpbrasil) ou
 * {@link SimuladorApplication} (simulação) neste processo, com o modo imposto como na CLI (argumentos do
 * Spring: {@code safira.simulacao.enabled} e exclusão das auto-configurações do outro modo; depois da
 * partida, uma única fonte de confiança do tipo do modo), sempre em loopback, com ociosidade opcional
 * ({@link MonitorDeOciosidade}).
 */
final class ExecucaoDoServidor {

    static final String LOOPBACK = "127.0.0.1";
    static final String VARIAVEL_OCIOSIDADE = "SAFIRA_IDLE_TIMEOUT";

    private static final Pattern SIMPLES = Pattern.compile("(\\d{1,9})([smh])");

    private ExecucaoDoServidor() {
    }

    /** Argumentos do Spring do servidor no modo (precedência máxima, acima de ambiente e propriedades). */
    static List<String> argumentos(Modo modo, int porta, Path pkiDir, Path config) {
        List<String> argumentos = new ArrayList<>(List.of(
                "--server.address=" + LOOPBACK,
                // Actuator sempre no mesmo conector (loopback): anula um management.server.port vindo de
                // --config ou do ambiente. Impor management.server.address=127.0.0.1 não serve: o Spring Boot
                // recusa a partida quando há endereço sem porta própria (o mesmo vale, falhando fechado, para um
                // management.server.address do usuário).
                "--management.server.port=",
                "--server.port=" + porta,
                "--safira.simulacao.enabled=" + modo.simulacao(),
                "--spring.autoconfigure.exclude=" + String.join(",", modo.excluidas()),
                "--logging.level.root=INFO",
                "--logging.level.eu.europa.esig=WARN"));
        if (!modo.simulacao()) {
            // o padrão do safira-app (/var/safira) é de implantação; localmente, o mesmo acervo da CLI
            argumentos.add("--icpbrasil-truststore.filesystem.base-dir="
                    + "${SAFIRA_TRUSTSTORE_DIR:${user.home}/.safira/icpbrasil-truststore}");
        }
        if (pkiDir != null) {
            argumentos.add("--safira.simulador.diretorio=" + pkiDir.toAbsolutePath());
        }
        if (config != null) {
            argumentos.add("--spring.config.additional-location=file:" + config.toAbsolutePath());
        }
        return argumentos;
    }

    /**
     * Tempo de ociosidade: {@code 90s}, {@code 30m}, {@code 2h} ou ISO-8601 ({@code PT30M}); vazio ou nulo =
     * desligada. Precisa ser positivo.
     */
    static Optional<Duration> ociosidade(String valor) {
        if (valor == null || valor.isBlank()) {
            return Optional.empty();
        }
        String texto = valor.strip();
        Duration duracao;
        try {
            Matcher simples = SIMPLES.matcher(texto);
            if (simples.matches()) {
                long quantidade = Long.parseLong(simples.group(1));
                duracao = switch (simples.group(2)) {
                    case "s" -> Duration.ofSeconds(quantidade);
                    case "m" -> Duration.ofMinutes(quantidade);
                    default -> Duration.ofHours(quantidade);
                };
            } else {
                duracao = Duration.parse(texto);
            }
        } catch (ArithmeticException | DateTimeParseException | NumberFormatException e) {
            throw invalida(valor);
        }
        if (duracao.isNegative() || duracao.isZero()) {
            throw invalida(valor);
        }
        return Optional.of(duracao);
    }

    private static FalhaDeUso invalida(String valor) {
        return new FalhaDeUso("Tempo de ociosidade inválido: '" + valor + "' (use 90s, 30m, 2h ou ISO-8601 como PT30M).");
    }

    /**
     * Sobe a aplicação do modo e bloqueia até o contexto fechar (SIGTERM aciona o desligamento gracioso
     * do Spring pelo gancho de desligamento).
     */
    static void executar(Modo modo, int porta, Path pkiDir, Path config, Duration ociosidade)
            throws InterruptedException {
        SpringApplication aplicacao = modo.simulacao() ? SimuladorApplication.aplicacao()
                : new SpringApplication(SafiraApplication.class);
        MonitorDeOciosidade monitor = ociosidade != null ? new MonitorDeOciosidade(ociosidade) : null;
        if (monitor != null) {
            aplicacao.addInitializers(inicial -> inicial.getBeanFactory()
                    .registerSingleton("safiraMonitorDeOciosidade", monitor));
        }
        ConfigurableApplicationContext contexto = aplicacao.run(argumentos(modo, porta, pkiDir, config)
                .toArray(String[]::new));
        CountDownLatch fechado = new CountDownLatch(1);
        contexto.addApplicationListener(new ApplicationListener<ContextClosedEvent>() {
            @Override
            public void onApplicationEvent(ContextClosedEvent evento) {
                fechado.countDown();
            }
        });
        try {
            ContextoSafira.exigirFonteUnica(contexto, modo);
        } catch (RuntimeException e) {
            contexto.close();
            throw e;
        }
        if (monitor != null) {
            monitor.vigiar(contexto);
        }
        fechado.await();
    }
}
