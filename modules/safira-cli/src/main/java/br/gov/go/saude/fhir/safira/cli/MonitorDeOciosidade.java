/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.fhir.safira.cli;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;

import java.io.IOException;
import java.time.Duration;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Encerra o servidor local depois de um tempo sem requisições ({@code --ociosidade} ou
 * {@code SAFIRA_IDLE_TIMEOUT}). As sondas em {@code /actuator/**} (ex.: {@code safira servidor status})
 * não contam como uso.
 */
final class MonitorDeOciosidade implements Filter {

    private static final Logger log = LoggerFactory.getLogger(MonitorDeOciosidade.class);
    private static final long VERIFICACAO_MINIMA_MS = 200;
    private static final long VERIFICACAO_MAXIMA_MS = 30_000;

    private final Duration limite;
    private final AtomicLong ultimoUso = new AtomicLong(System.nanoTime());

    MonitorDeOciosidade(Duration limite) {
        this.limite = limite;
    }

    @Override
    public void doFilter(ServletRequest requisicao, ServletResponse resposta, FilterChain cadeia)
            throws IOException, ServletException {
        if (!(requisicao instanceof HttpServletRequest http) || contaComoUso(http.getRequestURI())) {
            ultimoUso.set(System.nanoTime());
        }
        cadeia.doFilter(requisicao, resposta);
    }

    /** Toda requisição conta como uso, exceto {@code /actuator} e {@code /actuator/**}. */
    static boolean contaComoUso(String caminho) {
        return !"/actuator".equals(caminho) && !caminho.startsWith("/actuator/");
    }

    /** Verifica periodicamente (thread daemon) e encerra a aplicação e a JVM ao passar do limite. */
    void vigiar(ConfigurableApplicationContext contexto) {
        ultimoUso.set(System.nanoTime());
        long periodo = Math.clamp(limite.toMillis() / 4, VERIFICACAO_MINIMA_MS, VERIFICACAO_MAXIMA_MS);
        ScheduledExecutorService agenda = Executors.newSingleThreadScheduledExecutor(tarefa -> {
            Thread thread = new Thread(tarefa, "safira-ociosidade");
            thread.setDaemon(true);
            return thread;
        });
        agenda.scheduleAtFixedRate(() -> {
            if (System.nanoTime() - ultimoUso.get() >= limite.toNanos()) {
                log.info("Servidor ocioso há {}; encerrando.", limite);
                agenda.shutdown();
                System.exit(SpringApplication.exit(contexto));
            }
        }, periodo, periodo, TimeUnit.MILLISECONDS);
    }
}
