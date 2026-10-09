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
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;

/**
 * Lado do processo filho de {@code safira servidor}: roda {@link SafiraApplication} (icpbrasil) ou
 * {@link SimuladorApplication} (simulação) neste processo, com o modo imposto como na CLI (argumentos do
 * Spring: {@code safira.simulacao.enabled} e exclusão das auto-configurações do outro modo; depois da
 * partida, uma única fonte de confiança do tipo do modo), sempre em loopback.
 */
final class ExecucaoDoServidor {

    static final String LOOPBACK = "127.0.0.1";

    private ExecucaoDoServidor() {
    }

    /** Argumentos do Spring do servidor no modo (precedência máxima, acima de ambiente e propriedades). */
    static List<String> argumentos(Modo modo, int porta, Path pkiDir, Path config) {
        List<String> argumentos = new ArrayList<>(List.of(
                "--server.address=" + LOOPBACK,
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
     * Sobe a aplicação do modo e bloqueia até o contexto fechar (SIGTERM aciona o desligamento gracioso
     * do Spring pelo gancho de desligamento).
     */
    static void executar(Modo modo, int porta, Path pkiDir, Path config) throws InterruptedException {
        SpringApplication aplicacao = modo.simulacao() ? SimuladorApplication.aplicacao()
                : new SpringApplication(SafiraApplication.class);
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
        fechado.await();
    }
}
